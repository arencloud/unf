# ADR 0016: Pinned last-known-good enforcement maps

Status: Accepted for Phase 2 restart recovery

Amended by [ADR 0017](0017-transactional-identity-banks.md), which moves the
default pin layout from the six-map ABI v1 set to the nine-map ABI v2 set. The
decision below records the initial recovery boundary.

## Context

The policy compiler already activates one validated inactive bank with a single
`POLICY_CONFIG` write, but all enforcement maps previously belonged to one agent
process. Restarting that process recreated empty maps and temporarily returned the
overlay to its intentional unknown-state fail-open behavior. Readiness became true
as soon as the classifier attached, before controller reconciliation completed.

## Decision

The agent pins `IDENTITY_V4`, `IDENTITY_V6`, `POLICY_RULES`, `POLICY_IPV4`,
`POLICY_IPV6`, and `POLICY_CONFIG` under `/sys/fs/bpf/unf/v1` by default. The path
is configurable with `--bpf-pin-path` or `UNF_BPF_PIN_PATH`; the version component
is the explicit map-layout migration boundary. Telemetry maps remain ephemeral.

Startup requires the persistent set to be either wholly absent or wholly present.
Existing maps are reopened and checked for expected capacity. The agent rebuilds
its userspace identity and per-bank policy caches, rejects incompatible values,
requires one coherent nonzero identity revision, and verifies the configured
active policy bank's entry count and revision before adopting it. It never deletes
or silently replaces partial/corrupt pins.

A controller-managed agent becomes Ready only after both initial snapshot epochs
are applied, unless a complete pinned last-known-good identity and policy state was
validated. Recovered policy epoch/revision is reported immediately. Identity
revision is reported, but its source epoch remains unknown until controller
reconciliation, so cluster convergence is not falsely acknowledged.

## Consequences

A replacement agent can reattach a classifier backed by the previous enforcement
state without waiting for the controller. The kind verifier proves this by taking
the controller offline, restarting the agent on the demo server node, requiring
recovered readiness/revisions, and rechecking the allowed and denied flows before
restoring the controller.

Identity reconciliation remains single-bank. A crash during its mutation can
produce mixed revisions; recovery rejects that state and holds readiness rather
than claiming last-known-good safety. TC links are still process-owned, so there is
an attachment interval between the old process exiting and the replacement
attaching. Dual-bank identity activation and atomic pinned TCX link replacement
(with a documented legacy-netlink strategy) are separate hardening gates.
