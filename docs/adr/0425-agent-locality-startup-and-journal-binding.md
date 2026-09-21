# ADR 0425: Agent locality startup and real journal binding

Date: 2026-09-21

Status: implemented; paired real-process qualification pending

The agent now establishes one owned, withdrawn locality runtime before spawning
control-plane tasks, resolving the CNI provider, restoring remote routes or
serving CNI. Provider resolution can migrate a legacy journal, so it must follow
the early fence too. The runtime lives in `AgentState`, and the main BPF loader
binds and verifies the exact four held map IDs before any program attachment.
The main ELF declares the separate locality-v1 island; core ABI 15 and encryption
ABI 2 layouts remain unchanged. There is no packet dispatch in this slice.

## Durable startup boundary

A private `locality-runtime.json` checkpoint beside the attachment journal binds
the kernel boot ID, Node name and exact journal/pin paths. An exclusive regular
file owner lock is retained by the runtime and every bank/preparation using it.
Complete existing pins are reopened and withdrawn, never treated as permission.
Absent pins with a checkpoint from the same kernel boot stop startup. A validated
different kernel boot allows fresh empty maps, not restoration of old bank or
lease authority. Missing checkpoint plus schema-5 journal also stops startup.
First deployment with a pre-floor journal may create fresh maps; interrupted
first creation may reopen its complete set. No unknown inventory is deleted.

The checkpoint is durably persisted while holding map ownership, before the real
CNI journal is upgraded. A fresh `IncarnationGate` is installed on the actual
server journal before its listener or readiness heartbeat is published. The
server rejects an existing live socket before journal initialization. Any gate
failure stops bind; an unhooked schema-5 journal cannot report Ready, including
capability-only agent mode. Existing attachment records are preserved. The
schema-5 rollback boundary from ADR 0421 remains intentional: do not deploy an
old schema-4 reader or reset the journal to bypass it.

## Verification and remaining work

Local tests cover first/interrupted startup, same-boot missing pins, new-boot
decision, missing/foreign checkpoint rejection, real CNI initializer ordering,
live-socket exclusion and failed/unhooked initialization before readiness.
The workspace, strict Clippy and main BPF build must pass before commit.

The `kernel-agent-startup` diagnostic runs the actual current agent inside
disposable bpffs/state paths, without credentials, controller, uplinks or host
mounts. An intentionally missing ELF stops it before packet attachment. It
checks real early ownership, schema-5 installation, armed reopen withdrawal,
partial-pin refusal and same-boot missing-pin refusal while old map/program
descriptors remain alive. Full process output, including deliberate terminal
errors, is retained. All prior native/kernel/socket/reader-floor checks remain
required. This must pass cl02 before identical-image Kind.

This is not a fleet rollout, actual kernel-reboot continuity proof or packet
integration qualification. Applied identity/route writer hooks, authenticated
bank production, policy/Service/egress/reverse-path continuations and L3/L4/L5/Q
remain open. Production stays `45d85d5`; release pins and journals are unchanged.
