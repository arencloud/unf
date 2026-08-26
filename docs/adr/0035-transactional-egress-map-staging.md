# ADR 0035: Transactional egress map staging

## Status

Accepted and implemented. Egress lookup and controller admission remain gated.

## Context

Source-selected egress lowering produces two new key families that cannot share
the meaning of ingress address keys. Activating either family independently
would expose a partial policy revision. Reusing the v2 pin directory would also
let an older program reopen state whose complete map set it does not understand.

## Decision

Policy snapshot schema v4 adds IPv4 and IPv6 egress entry lists. Policy map ABI
v3 adds fixed-layout `EGRESS_IPV4` hash and `EGRESS_IPV6` LPM maps and moves the
complete persistent set to `/sys/fs/bpf/unf/v3`.

IPv4 keys contain destination address, selected source identity, destination
port, protocol, and bank. IPv6 LPM data contains the exact source identity,
port, protocol, bank, and destination prefix. Both retain the existing
fixed-size decision value and its actual/shadow provenance.

The agent treats identity, ingress identity, ingress IPv4, ingress IPv6, egress
IPv4, and egress IPv6 state as one recovery and activation unit. It replaces and
reads back every inactive policy map, writes `POLICY_CONFIG` only after all five
policy banks validate, and rolls every staged map back on any failure. The
config entry count and agent metric cover all policy maps.

Cleanup recognizes historical v1 and v2 ownership sets plus the eleven-pin v3
set. Current v3 deletion still requires explicit confirmation. Deployment,
fault injection, TC handoff, and coordinated OpenShift uninstall use the v3
path and exact map count.

The controller emits empty egress lists while its ingress-only NetworkPolicy
admission gate remains active. The eBPF object declares and pins both maps but
does not consult them yet, so this ABI migration cannot change forwarding.

## Verification

Shared ABI tests fix both key sizes and alignments. Agent tests verify byte-order
encoding, source/destination placement, prefix length, revision/value ABI,
transport validation, snapshot schema, historical cleanup recognition, and
current-ABI refusal. Workspace formatting, strict lint, tests, and the release
eBPF build are required.

The rebuilt two-node Kind gate must additionally prove all eleven v3 pins,
transactional ingress updates and rollback, last-known-good restart recovery,
TCX and legacy handoff, scoped stale-v1 cleanup, and unchanged dual-stack ingress
enforcement before this staging boundary is considered live-qualified. A fresh
dual-stack cluster passed that complete gate after the v3 migration.

## Consequences

Every map needed by egress enforcement can now be distributed under one atomic
revision without weakening existing ingress. The separate ABI directory makes
the upgrade boundary explicit and leaves v2 state available for deliberate
retirement rather than mutating it in place.

ADR 0036 subsequently added source-selected egress map lookup, deny composition,
and policy-direction provenance in TC. The controller still emits empty egress
lists. Simulation/status integration and live egress lifecycle qualification
remain later steps.
