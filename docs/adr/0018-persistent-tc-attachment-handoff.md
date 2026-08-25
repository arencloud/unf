# ADR 0018: Persistent TC attachment handoff

Status: Accepted for Phase 2 restart continuity

## Context

ADRs 0016 and 0017 made the active identity and policy state persistent and
transactional, allowing a replacement agent to recover last-known-good
enforcement without the controller. The classifier attachment itself still
belonged to the agent process. Exiting detached the old program before the
replacement could load and attach, creating a fail-open interval even though the
maps were valid.

UNF must coexist with an existing CNI and must not remove or replace unrelated TC
state. It also needs a defined path for kernels both with and without TCX.

## Decision

The agent selects and reports one attachment mode from the host kernel release:

- Linux 6.6 and newer uses `tcx_pinned`. For each discovered non-loopback
  interface in the configured ingress or egress direction, the agent creates a
  TCX attachment with explicit last ordering and pins its link as
  `/sys/fs/bpf/unf/v2/links/tcx-{direction}-{ifindex}`. A replacement opens the
  existing pin and updates the link to its already loaded program with
  `bpf_link_update`. Closing the userspace link descriptor does not remove the
  pinned attachment.
- Older kernels use `legacy_netlink`. UNF owns priority `0x554e` with handle
  `0x554e:1` for ingress and `0x554e:2` for egress. A replacement first opens that
  exact filter identity and replaces its program in place. If the filter does not
  exist, it creates it with the same tuple. The agent deliberately transfers the
  detach guard's lifetime to the kernel so process exit does not remove the
  filter.

Interface tracking includes both name and index so name reuse triggers a new
attachment. TCX cleanup only removes direction-specific UNF pin names with a
numeric interface index that is no longer present. It does not scan or delete
arbitrary bpffs objects. An existing pin that cannot be opened as the expected
TCX link is an attachment error; the agent does not silently replace it.

The public agent status includes `tc_attachment_mode` with `none`, `tcx_pinned`,
or `legacy_netlink`, making kernel-specific behavior visible to operators.
ADR 0021 adds an explicit mode preference for compatibility testing while
retaining automatic kernel-based selection as the default.

## Consequences

The old classifier remains active until the replacement has loaded its program
and performs an in-place handoff. The Linux 7.1 two-node kind verifier deletes an
agent with the controller offline, runs parallel requests continuously against an
explicitly denied TCP/9090 flow, requires zero successes, and then requires the
replacement to report pinned TCX mode and atomic-update evidence.

The same host now also live-verifies the legacy implementation by explicitly
selecting it, confirming its reserved kernel filter, removing UNF's TCX pins, and
repeating the offline-controller replacement under the continuous deny probe.
The gate restores TCX before deleting the legacy filters, so cleanup never removes
the only active UNF attachment.

The fixed legacy tuple avoids accumulating filters and gives restart replacement
a stable identity, but can conflict with an independently configured filter using
that reserved tuple. Its implementation, selection boundary, and in-place
replacement path now have unit and live-kernel coverage on Linux 7.1. Older RHEL,
OpenShift, and other pre-6.6 supported kernels must still validate native fallback
selection and host compatibility before receiving the same platform-support
claim.

Pinned links and persistent legacy filters need explicit operator cleanup during
uninstall or ABI retirement. Automated production cleanup is separate work
because deleting host networking state must be deliberate and scoped.
