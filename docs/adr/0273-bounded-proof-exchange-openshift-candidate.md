# ADR 0273: Bounded proof exchange OpenShift candidate

Date: 2026-09-12

Status: Deployment verified; Required migration rejected by cl02

Runtime `c02e060248ce52c0e498dcc31b13acfcadaa01b4` combines ADRs 0270–0272:
indexed fair probe exchange, lifetime-bound admitted catalog reuse and atomic
proof batches capped at 64 items. Public immutable controller and agent digests
are pinned in the Phase 9 release record and Kustomization. The test-tools
digest is unchanged. Kind evidence is explicitly pending, not inherited.

All 722 workspace tests passed with 22 privileged tests ignored by the generic
invocation. Strict full-workspace all-target/all-feature Clippy, formatting and
the OpenShift static gate passed. The independent isolated kernel WireGuard
fixture passed 4,096 rounds per family, peer-loss denial and fresh recovery,
positive duplex counters and ciphertext-only capture. New commits passed a
redacted secret scan; credentials and raw lab evidence remain outside Git.

The exact images require preserved-state cl02 deployment and the full Required,
selective, ciphertext, failure, rotation, replacement, operations and cleanup
gate at the normal 2-GiB controller limit. Only a cl02 pass permits fresh Kind
qualification. ADR 0269's checkpoint-size gap and the pre-existing operator
health problems remain explicit in the stabilization tracker. Publication
does not close Phase 9 or establish heavy-load readiness.

## cl02 result and follow-up diagnosis

Harness `7ec5b13` passed exact preserved-state deployment with all five agents
converged. The archived deployment evidence SHA-256 is
`320b5886f0fca9f3e6846fc20ed9086486ee6575f0c849450c615926748454ad`.
The full gate again timed out at Required migration and restored Native mode.
No UNF container restarted. The transient compressed-checkpoint size error
recurred (913,347 bytes against the unchanged 900,000-byte bound).

Unlike the predecessor, this runtime recorded completed remote quorums and
agents repeatedly reached receipt-to-generation validation. Inspection found
a concrete compatibility gap: replicated identities compile multiple plans
into one address-bound decision with an aggregate witness and no direct
transport ID, but receipt validation requires one receipt per decision and a
direct transport ID. It therefore cannot admit those replicated decisions.
The fix must prove the complete original plan-witness set against the aggregate,
not discard surplus receipts or weaken transport checks.

An authenticated read-only diagnostic fetched receipts from one worker; its
raw API exec stream timed out and only a prefix was recoverable. That prefix
is not complete qualification evidence. A subsequent in-cluster summary and
code inspection informed the diagnosis. The failed gate remains failed, and
Kind remains pending.
