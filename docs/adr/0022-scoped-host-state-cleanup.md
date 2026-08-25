# ADR 0022: Dry-run-first scoped host-state cleanup

Status: Accepted and live verified for Phase 2 operations

## Context

ABI migration and persistent attachment handoff deliberately leave kernel-owned
state beyond an agent process lifetime. ABI v1 map pins can remain after a v2
rollout, TCX pins survive replacement, and legacy netlink filters remain installed
for in-place handoff. Generic recursive deletion or qdisc removal could destroy
unknown bpffs content, active enforcement, or another component's TC state.

Cleanup must therefore expose its ownership decision before mutation, refuse
ambiguous state, and require more authority for the currently deployed ABI.

## Decision

Add `unf-agent cleanup` as a privileged, per-node operational command. It is a
non-mutating dry run unless `--execute` is supplied. At least one explicit scope
is required:

- `--abi-version 1|2` derives one directory below `/sys/fs/bpf/unf`. Only the
  known map names for that ABI and `links/tcx-{ingress|egress}-{ifindex}` pins are
  removable. The root and target must be real, safe directories. Unknown entries,
  symbolic links, non-numeric link names, and unsupported ABI versions abort the
  whole plan before mutation. Current ABI v2 additionally requires
  `--allow-current-abi`.
- `--legacy-attachments` requires either `--all-interfaces` or one or more exact
  `--interface` values and an ingress, egress, or both direction. Detachment uses
  the exact UNF program names. A missing named filter is an idempotent success;
  clsact and unrelated filters are never removed.

Execution unlinks each planned pin and removes only the now-empty `links` and ABI
directories. Directory removal remains non-recursive so a concurrent unknown
entry causes a safe failure. The command does not stop agents, coordinate a
rollout, or prove that a replacement attachment is enforcing; operators must do
that before current-state or migration cleanup.

## Verification

Unit tests cover dry-run CLI defaults, exact TCX-name matching, current and
unsupported ABI refusal, root/target symlink refusal, unknown-content refusal
without mutation, and exact planned removal while preserving a sibling entry.

The two-node kind gate uses the deployed agent binary to reject current v2
without confirmation, inject unknown content into recognized v1 state and prove
non-mutation, remove that content, prove a dry run retains all v1 pins, then
execute cleanup on both nodes. It requires v1 to be absent and all nine v2 map
pins to remain. The legacy gate restores and verifies TCX first, proves legacy
cleanup dry-run non-mutation, executes the same command, and confirms the reserved
legacy filters are absent.

## Consequences

ABI retirement and uninstall now have a reviewable, idempotent ownership boundary
instead of requiring ad hoc recursive deletion. The command intentionally favors
refusal over cleanup when state is unfamiliar. Production orchestration, native
pre-6.6 validation beyond the qualified OpenShift/RHCOS Linux 5.14 environment,
and a coordinated OpenShift uninstall/cleanup drill remain separate work. The
runtime qualification already verifies the reserved legacy filters under the
privileged SCC with SELinux Enforcing.
