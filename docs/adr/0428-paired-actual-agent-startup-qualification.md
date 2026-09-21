# ADR 0428: Paired actual-agent startup qualification

Date: 2026-09-21

Status: disposable actual-startup scope verified; full integration open

The rebuilt complete `kernel-agent-startup` gate passes on cl02 first and then
persistent Kind, retaining ADR 0426's failed attempt. Both use exact source
`4a027ea` and immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:3b965bac2f0686b282214bfcc9a9b7c4933004d14bbbd75edbf7f5df96bb407a`

The actual agent executable SHA-256 is
`808cb7de86d612affe20d69a1c2ffd4653d8b4486d6a47a04afb7dc86c08d45f`.

Five real-process scenarios pass on each platform: fresh owned startup/real CNI
journal-floor installation, missing system trust as a supervised exit-1 error,
armed same-boot reopen withdrawal, incomplete pin-set rejection, and refusal to
recreate absent same-boot pins while old maps/program remain descriptor-held.
No panic or timeout is accepted. Complete deliberate failure output is retained.
Checkpoint and private journal bytes are preserved across reopen/rejection.
The intentionally missing main ELF prevents any TC packet attachment by this
agent. The kernel-boot transition remains a local decision test, not a real
reboot qualification.

All original 28 native checks, nineteen bank decisions, eight coordinated-writer
decisions, eight successful dual-stack TCP/UDP exchanges, sixteen socket denials,
runtime-owner checks and actual frozen-old-agent reader-floor rejection also
pass. Both diagnostic processes exit zero without restart; private resources and
exact-UID Kubernetes Namespaces are removed, with absence confirmed.

## State and log review

Both production fleets remain `45d85d5`, Native, with no runtime/release pin,
production journal or packet-path change. Before/after production journals are
byte-identical. Current UNF Pods remain Ready with zero restarts.

Full regular/init and retained/rotated logs are reviewed. Current cl02 retains
453 warnings: 414 bounded flow-history, 34 peer-proof retries, four bounded
topology-history and one attestation-row rejection. Retained cl02 CRI has 5,365
warnings in 21 categories. Kind has no current warnings/errors and 65 retained
warnings in twelve categories. Overlapping inventories are not additive. No
production ERROR, observer failure, partial or non-JSON retained record is found.
Expected diagnostic terminal errors are separate retained test evidence, not
hidden production errors. Existing warnings remain stabilization findings.

Evidence prefix: `.artifacts/p9-kernel-agent-startup-4a027ea-{cl02,kind}`.

| Evidence | SHA-256 |
|---|---|
| cl02 result | `b05faa5bedbfe73b2e5d41c4cea1074ce2ef743d9478f8e0a795c9bc6c19edd2` |
| cl02 complete log | `074adce0aa9c804a7ac773dc3c85887e87417e01fb91edd53a86d25fab7e6412` |
| Kind result | `54d8ce59b1150225959c42598535baa9ab5357a62a329d652fe82627c64fa107` |
| Kind complete log | `64c2ae6f49a29abd4aae6d562959748cc8720b06d7c764a6138a6a5d3c2f7197` |

This qualifies actual early startup and supervised client failure, not main-ELF
attachment, applied-writer integration, bank publication or production policy/
Service/reply composition. The newer `c7aece1` writer code passed 906 local
workspace tests and strict Clippy but is not present in this fixed-source image.
Continue actual bank production and packet wiring, then L3/L4/L5/Q. Phase 9 and
the measured S1–S5 stabilization program remain open.
