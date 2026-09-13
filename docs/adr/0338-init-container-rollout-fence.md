# ADR 0338: Init-Container Failure Fence During Runtime Rollout

Date: 2026-09-13

Status: metadata guard verified locally; live positive readback checked on cl02 then Kind

Before matching Kind CNI rollout, the shared staging guard is extended to
include `initContainerStatuses`. Previously it rejected failures/restarts only
in regular containers, covering OpenShift's regular installer but not Kind's
init installer. A candidate must not advance after an init failure or restart
even if its regular agent eventually starts successfully.

Successful zero-restart init completion is explicitly valid. A nonzero exit,
non-Completed termination reason, signal, prior termination, restart or fatal
waiting state is rejected. Regular-container termination remains rejected.
The guard still allows healthy pending startup without requiring the global
management-readiness barrier before all candidates can be staged.

The earlier regression cases pass, plus positive running/completed init cases
and seven negative init mutations. Read-only current-Pod observations pass on
cl02's `450de80` regular-installer topology first, then retained Kind's existing
`67c2772` init-installer topology. These observations do not inject live failures
or qualify the pending new Kind runtime. No image, Pod, journal or BPF state
changes in this slice. The current Rust baseline remains 787 passing tests.

Matching Kind rollout must additionally verify the installed CNI hash and a
zero-grace live protocol response after each init/agent startup, preserving
the original installer topology and durable state. The complete expanded
CNI/Required reply gate follows rollout. L3, L4/L5/Q and S1–S5 remain open.
