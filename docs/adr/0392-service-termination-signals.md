# ADR 0392: Container Termination Uses the Service Drain Path

Date: 2026-09-21

Status: regression-backed implementation; live PID-1 and fabric recovery pending

ADRs 0390–0391 preserve an operational defect: both immutable image-check
containers require SIGKILL after their SIGTERM grace. Each service's main wait
previously listened only for Ctrl-C. New real-child-process regressions fail
for SIGTERM in both binaries (exit by signal 15 rather than successful task
drain), while both SIGINT controls pass. They signal only their freshly spawned
child, clear inherited configuration, bind loopback, and reap it on failure.

The small userspace-only `unf-runtime` crate registers SIGINT and SIGTERM
streams before either service starts background tasks. Holding these streams
also retains an early signal until the main shutdown wait. No task polls for
signals, no packet path changes, and the no-std common crate gains no runtime
dependency. Both signals now enter the existing cancellation/join path;
agent supervised-failure handling remains separate and unchanged. Registration
failure is a startup error. Non-Unix platforms retain Ctrl-C support.

Shutdown request/completion messages are bounded lifecycle events. OpenShift's
agent filter admits that target without enabling per-packet INFO output.
No shutdown path invokes the destructive cleanup command or resets authority,
maps, journals, key frontiers or transport state. Signals received during long
initialization wait for initialization to reach the drain point; this change
does not promise bounded startup cancellation or a universal drain deadline.

The green local suite passes 825 tests, with 26 privileged tests ignored, and
strict all-target workspace Clippy. `hack/verify-service-shutdown.sh` supplies
the next isolated live gate: exact immutable revision, unprivileged read-only
PID-1 Pods, SIGTERM and SIGINT for each service, zero exit status/restarts,
request/completion logs, observer success and exact owned-Namespace cleanup.
It explicitly does not qualify a fully configured fabric's shutdown.
The first cl02 attempt is retained: Pod-proxy version observation was rejected
before any signal; the observer now uses an owned localhost-only port-forward.
The corrected cl02 red run reaches the old controller as PID 1, verifies
`8db97bb`, sends SIGTERM successfully, and observes it still Running with zero
restarts through ten subsequent observations. The owned fixture is removed;
no live fabric process is signalled. Both failed attempts remain in evidence.

Package static safety/render checks pass. The separate workstation installer
mock does not: its container cannot connect to the host socat socket under
SELinux (permission denied), matching the retained earlier fixture failure.
This is not a successful installer qualification and no platform security
setting is weakened to hide it.

Next: cl02 isolated qualification before matching Kind, then guarded real
runtime recovery/traffic validation. L3 production locality, L4/L5/Q and S1–S5
remain open. No release pin changes or credential commits are authorized by
this local result.
