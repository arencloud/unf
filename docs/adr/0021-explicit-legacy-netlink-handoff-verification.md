# ADR 0021: Explicit legacy netlink handoff verification

Status: Accepted for Phase 2 attachment compatibility validation

## Context

ADR 0018 selects pinned TCX on Linux 6.6 and newer and persistent netlink filters
on older kernels. The development and CI host supports TCX, so the automatic path
could not exercise legacy filter installation or replacement. Static coverage did
not prove that Aya can reopen the fixed kernel filter identity, replace its
program in place, and preserve enforcement across process replacement.

Running TCX and legacy classifiers together would also produce weak evidence:
traffic might remain denied because TCX was still attached. Removing either mode
during a test requires ordered, scoped cleanup so validation itself does not open
an enforcement gap or leave duplicate classifiers behind.

## Decision

The agent accepts `--tc-attachment-mode` or `UNF_TC_ATTACHMENT_MODE` with three
values:

- `auto` retains kernel-release selection and remains the production default;
- `tcx-pinned` explicitly requests pinned TCX; and
- `legacy-netlink` explicitly requests the fixed netlink filter path.

Explicit selection changes no priority, handle, pin, or ownership boundary. An
unsupported explicit choice fails through the normal attachment error path; it
does not silently fall back to another mode. Agent status continues to report the
actual selected mode.

After the normal kind gate proves TCX handoff, a dedicated verifier deploys the
test-only host-network helper and selects legacy mode. It requires every agent to
converge and the server node to expose UNF's ingress filter at priority `0x554e`
(21838), handle `0x554e0001`. On a TCX-capable host it then unlinks only
`tcx-ingress-*` pins below UNF's ABI link directory, ensuring traffic evidence can
come only from the legacy attachment.

With the controller offline, the verifier continuously probes an explicitly
denied flow while replacing the server-node agent. The replacement must recover
pinned policy state, report `legacy_netlink`, log `replaced=true`, retain the
single reserved filter identity, allow TCP/8080, and deny TCP/9090 without a
successful probe. Cleanup first returns agents to automatic TCX mode and confirms
new TCX pins, then deletes only priority 21838/handle `0x554e0001` filters. A trap
uses the same ordering after early failure. On a host whose automatic mode is
already legacy, the transition and cleanup are omitted so native attachments are
not disturbed.

## Consequences

The fixed legacy replacement path now has repeatable live-kernel evidence even on
the TCX-capable development host, and `make kind-test` exercises both attachment
implementations. The mode override is also available for controlled compatibility
diagnostics, but `auto` remains the deployment default.

This is not evidence that a pre-6.6 distribution kernel exposes every required
BPF/netlink capability, nor that OpenShift SCC, SELinux, CRI-O, or host networking
permits the design. Native older-kernel and OpenShift runs remain required before
making those platform-support claims. Production uninstall and ABI-retirement
cleanup also remain separate operator-facing work.
