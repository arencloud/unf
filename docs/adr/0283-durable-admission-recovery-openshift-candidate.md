# ADR 0283: Durable-admission recovery OpenShift candidate

Date: 2026-09-13

Status: Published; cl02 deployment and full platform qualification pending

Runtime `24a66ca946dee9f42b2f4d9fccfe2118838dde73` adds ADR 0281's exact,
authenticated durable-admission recovery to the bounded checkpoint fallback and
timeout responder candidate. The release record and overlay pin its public
controller/agent images by digest. Test tools are unchanged. Kind remains pending
with no invented evidence; qualification order is cl02 first, then fresh Kind.
ADR 0282 independently verifies bounded operations history in both full gates.

Local confirmation passed 728 workspace tests (25 specialized tests excluded),
strict all-target/all-feature workspace lint, the actual five-Node captured
frontier recovery test, and both platform static gates. The release controller
requires only the ordinary C/math/GCC runtime libraries, not dynamic libzstd.

The workstation's Btrfs metadata reservation failed during normal image assembly
after successful compilation. No existing images, user files, or filesystem
layout were removed or changed to bypass it. The same committed Containerfile
was rebuilt with isolated graph, run and image-copy scratch directories on
temporary storage. The existing Rust base was transferred and its image ID
independently matched; Debian was preloaded by its existing digest. Both builds
used `--pull=never` for those bases and the full runtime revision. Only resulting
runtime images, not builder images or operational credentials, were pushed.
Temporary local image storage is ephemeral; public digest pins are durable.

Immediately before this candidate, all five cl02 admission journals still named
generation `1789245125471` with exact predecessor `1789245078215`. This confirms
the admitted-fact selector can supply the missing cut, not merely a prepared
future plan. Each old agent exhausted its 900 fenced startup retries once and
exited with code 1; no OOM was reported. Six unhealthy operators still included
DNS/route timeouts. These are baseline failures, not successful qualification.

Deployment must preserve journals and pinned state, recover the missing frontier,
and prove actual encryption convergence. Pod readiness and configured Native
intent alone do not establish that. Then run the complete Required/selective,
ciphertext, failure, rotation/replacement, persistence, operations and exact
cleanup gate on cl02 before qualifying identical runtime images on Kind.
Phase 9 and stabilization/scale readiness remain unverified until their separate
exit criteria pass.
