# ADR 0273: Bounded proof exchange OpenShift candidate

Date: 2026-09-12

Status: Published; cl02 and subsequent Kind qualification pending

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
