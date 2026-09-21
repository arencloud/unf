# ADR 0448: Explicit cl02 locality lab capability profile

Superseded by ADR 0449: the operator selected the scoped helper before any live
capability change. Historical patch approval below is no longer the chosen plan.

## Decision

The operator selected option two from ADR 0445: add SYS_ADMIN to the cl02 lab
agent. This resolves the authorization hold, not runtime qualification. Keep
the agent non-privileged, NoNewPrivs, read-only root, RuntimeDefault seccomp and
SELinux enforcing with `spc_t`. Retain exactly BPF, NET_ADMIN, PERFMON and
SYS_ADMIN. Do not change the default deployment or treat this broad capability
as a least-privilege production recommendation.

Guarded opt-in JSON patches test the existing SCC and DaemonSet identity and
capabilities before modification. The OnDelete strategy prevents automatic
agent replacement. No image or journal is changed by these patches.

## Validation sequence

1. `bash hack/verify-locality-lab-profile.sh`: one positive and fourteen negative
   profile checks; syntax checks and `git diff --check`.
2. Server-side dry-run of both patches against cl02, retaining the original
   security fields and adding only SYS_ADMIN.
3. Run immutable diagnostic source `762c980` main and composition gates with
   `UNF_LOCALITY_GATE_SECURITY_PROFILE=cl02-sys-admin-lab`. Attest effective,
   permitted and bounding capabilities, NoNewPrivs, seccomp and enforcing
   SELinux inside the container. Retain admitted Pod and complete test logs.
4. Only after success apply the approved patches, dry-run the actual production
   Pod under `unf-primary-agent`, then stage the runtime with journal preservation,
   actual capability/version readback and all-Pod log review.

The disposable diagnostic account uses privileged SCC authorization to admit
bounded emptyDir scratch space (the production SCC permits no emptyDir). Its
container is explicitly non-privileged with the exact profile, no hostPath, and
runtime attestation. This is not proof of production-SCC admission or full fleet
reconciliation. Do not add capabilities or weaken SELinux/seccomp to pass a test.

## Status

Local checks and server-side patch dry-runs pass. Exact-profile kernel/socket
qualification, actual patch application, runtime shutdown/version qualification,
schema-5 migration, authenticated fleet/recovery, matching Kind and full Phase 9
closure remain pending. Production remains source `45d85d5` on both platforms.
No existing journals, maps or histories were reset.
