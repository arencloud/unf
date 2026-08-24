# ADR 0017: Transactional dual-bank identity activation

Status: Accepted for Phase 2 identity consistency

## Context

Policy updates already stage complete inactive banks and activate them with one
configuration-map write. Identity reconciliation instead mutated the active IPv4
and IPv6 maps in place. A process or node failure between address-family updates
could leave a mixed revision. Recovery correctly fenced that state, but could not
preserve the last complete identity snapshot.

Identity keys are a public eBPF/userspace ABI used on every packet. Adding a bank
byte to them would enlarge both address-family keys and force extra key assembly
in TC. A complete identity snapshot can also be empty, so map contents alone
cannot distinguish an intentionally committed empty revision from fresh state.

## Decision

Use two physical maps per address family: `IDENTITY_V4`/`IDENTITY_V4_B` and
`IDENTITY_V6`/`IDENTITY_V6_B`. `IDENTITY_CONFIG[0]` is a fixed 24-byte atomic
pointer containing source epoch, revision, combined entry count, schema version,
active bank, and flags.

The agent replaces the inactive IPv4 and IPv6 maps, reads every desired entry
back, and writes `IDENTITY_CONFIG` only after both validations succeed. Any
pre-activation failure restores the previous inactive contents. After activation,
the former active maps retain their complete snapshot until they become the next
staging target. This avoids invalidating an in-flight packet that already copied
the old config; stale staging keys are removed before insertions so a full bank
can be replaced without transiently exceeding its capacity.

TC reads identity config once per packet and uses that same value for source and
destination lookup. A value is accepted only when its schema and revision match
the selected config. Missing or incompatible config/value state resolves to
identity zero and retains the documented fail-open behavior.

Identity map ABI version 2 and `/sys/fs/bpf/unf/v2` form the migration boundary.
The persistent set now contains nine maps: five identity maps and the existing
four policy maps. Startup requires the set to be wholly absent or wholly present.
Recovery validates every value structurally, then requires the selected identity
bank to match the config entry count and uniform revision. An inactive bank may
contain mixed revisions after an interrupted stage and is not adopted. A valid
config can select an empty bank, preserving a committed empty snapshot and its
source epoch across restart.

## Consequences

Identity updates no longer expose a partially mutated IPv4/IPv6 snapshot, and an
agent can recover the last activated identity epoch and revision while the
controller is unavailable. The design doubles physical identity-map capacity and
adds one array lookup per parsed packet, while preserving the existing address
key layouts.

ABI v1 pins are intentionally not deleted or migrated in place. Operators may
remove the old directory after validating the v2 rollout. TC attachments remain
process-owned, so attachment handoff and its restart interval are a separate
hardening gate.
