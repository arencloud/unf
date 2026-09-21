# ADR 0443: Thread-lifetime private bank pins

Date: 2026-09-21

Status: implemented; local checks pass; privileged qualification pending

The Aya loader needs temporary named pins to reuse the four exact live shared
maps. Normal temporary-directory cleanup handles ordinary return, but SIGKILL
can leave persistent pins and retain an old lease map. Do not solve this by
deleting arbitrary similarly named directories after restart.

Run only this synchronous pin/load/exact-ID-check section on a dedicated,
joined leaf OS thread. Unshare its FS context and mount namespace, never its
file-descriptor table. Mark the copied mount tree recursively private before
mounting a fresh bpffs over the existing managed empty preparation directory.
Create adapter pins only in that private filesystem. Return the loaded object
by its still-valid anonymous map/program FDs; no mount-namespace FD or worker
escapes. Device observation, sealing and admission retain their existing rules.

The last private namespace reference disappears at thread/process exit, also
after loader failure, panic or SIGKILL. Thus the kernel reclaims temporary pins
without a cleanup scan or persistent tombstones. The parent/host mount tree and
underlying preparation directory remain untouched. Unexpected prior residue
is refused and preserved before any namespace action. There is no shared-pin
fallback if namespace or mount setup fails. CAP_SYS_ADMIN is required by this
privileged loader; fleet qualification must check the actual SELinux context.

A dedicated ignored kernel test checks returned FD survival, map-ID reclamation
after success/error/panic, and SIGKILL of a child paused with a real pinned map.
It also checks the caller's mount namespace and underlying directory remain
unchanged, and preserves foreign residue. Child failure output is surfaced.
The immutable diagnostic now packages its locality-library test binary and
requires this test before the full publisher/DSR socket matrix. Exact four-test
count and a positive lifetime marker are mandatory.

The packaged bank ELF reader also opens NONBLOCK, so a substituted FIFO cannot
hang startup before the regular-file check. Existing size/ownership checks stay.

Local results: 913 workspace tests pass, 33 privileged tests ignored, strict
locality/agent all-target Clippy passes. The expanded image must pass cl02 first,
then identical Kind. This is not yet a verified kernel-lifetime result, whole
agent crash/restart proof, fleet rollout or resource-performance measurement.
Phase 9 L3/L4/L5/Q and S1–S5 remain open.
