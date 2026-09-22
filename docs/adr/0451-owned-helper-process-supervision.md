# ADR 0451: Owned helper process supervision

## Decision

Extend ADRs 0449–0450's detached-mount boundary with a fixed-purpose packaged
`unf-locality-helper` process and a persistent single-slot supervisor. This is
an isolated **privileged-bootstrap primitive**, not yet the final agent/helper
deployment. It explicitly requires existing SYS_ADMIN at launch and cannot
launch from the running three-capability agent. No file capabilities/setuid,
agent capability expansion, runtime image rollout or journal migration is added.

The packaged helper must be root-owned, non-writable by group/others, regular,
single-link native ELF, at most 32 MiB, opened without symlink traversal. Its
expected digest comes from trusted packaging, never RPC. Startup copies exactly
those digest-checked bytes into a write/grow/shrink/seal-locked memfd and executes
that held FD. This removes pathname replacement and subsequent executable-content
mutation from the launch boundary. No shell or inherited environment is used.
This startup memory cost is bounded and remains a stabilization measurement,
not a claimed performance improvement.

Each session has a random abstract Unix SEQPACKET rendezvous. The name is not
authorization: both sides require actual kernel PID/UID/GID credentials and
per-message credentials. The supervisor accepts only its unreaped owned child;
the worker accepts only its checked original parent. A pidfd binds cancellation
to the process instance. This slice requires a shared PID/network namespace;
it does not assume cross-container PID visibility or silently enable shared PID
namespaces on the live DaemonSet.

The worker accepts only the fixed mount operation. It sets NoNewPrivs, clears
ambient capabilities, restricts effective/permitted/bounding capabilities to
SYS_ADMIN, empties inheritable capabilities and disables dumpability. It arms
parent-death SIGKILL and rechecks the parent around registration. All changes are
inside the new worker, never the parent/agent or host. No persistent listener or
filesystem socket path is introduced.

One non-queuing supervisor slot spans launch, authenticated connection, response,
exit verification and actual reaping. Cancellation tokens are single-use. Drop,
cancel, timeout or protocol failure kill/reap the owned child before release;
no returned mount escapes an unsuccessful/cancelled session. An ambiguous reap
permanently fences the slot. A child stuck in uninterruptible kernel sleep may
delay reaping beyond the five-second operation deadline: never claim a hard
realtime kill guarantee or spawn a replacement while ownership is unresolved.
Blocking calls belong on a bounded worker, not an async executor thread.

## Checks

Local regressions cover immutable executable sealing, wrong digest, changed
length, script/symlink/special-file rejection, rendezvous encoding, cancellation
and retained/fenced slot ownership. Existing transport tests retain malformed,
truncated, stale and credential-substitution coverage. Strict Clippy is required.

The new `helper-process` kernel gate uses the packaged binary with compiled
source equality. It will verify an actual separate child, exact helper bounding
set/NoNewPrivs, same-UID three-capability client denied helper-memory access,
successful FD use/BPF pin reclamation, single-slot exclusion, token-reuse refusal,
deadline refusal, explicit cancellation and dropped-session reaping. Run it on
cl02 before identical Kind, retaining all logs and production journals.

## Current status and remaining work

Implementation and local checks are complete; live process qualification is
pending. Parent-process SIGKILL/orphan behavior is implemented but not yet covered
by this gate's explicit parent-death test. Full bank-loader integration, peer
impostor/crash-stage matrices, deployment-specific endpoint/bootstrap delivery,
separate container SCC/seccomp/SELinux, namespace observations and device seeding
remain required. Do not describe this primitive as a fully deployed helper or
mark Phase 9/L3/L4/L5/Q Verified. No packet-path IPC is introduced.
