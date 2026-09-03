# ADR 0120: Own egress dataplane banks under persistent ABI v12

**Status:** Accepted and implemented for the Phase 8.5 map-ownership slice

## Context

ADR 0119 fixed the egress packet ABI and pure compiler, but deliberately created
no kernel maps. Reusing the 25-pin v11 directory after adding new state would make
an older binary interpret a complete new directory as its own and would weaken
partial-set detection during rollback.

## Decision

Persistent BPF-state ABI v12 owns six additional maps:

- `EGRESS_SOURCES`, `EGRESS_ADDRESSES`, `EGRESS_GATEWAYS`, and
  `EGRESS_SELECTIONS` hold two immutable logical banks;
- `EGRESS_CONFIG[0]` is the sole activation pointer for all four tables; and
- `EGRESS_CONNECTIONS` reserves persistent bounded LRU ownership for the later
  dual-stack SNAT/reverse-flow stage.

The agent converts the asserted ABI-v1 structs to explicit fixed-width bytes,
replaces only the inactive bank, reads every staged entry back, and performs one
config write to activate it. Any pre-switch error restores the inactive bank and
leaves the active pointer untouched. Startup validates map types/capacities,
entry schemas, bank tags, config authority revisions, and all four declared
counts. The config pointer is authoritative: an uncommitted bank is removed on
recovery, and a zero config removes all orphan staging state.

ABI v9, v10, and v11 remain exact historical 25-map cleanup boundaries. Current
v12 is an exact 31-map all-or-none boundary and requires explicit authority for
cleanup. The operational manifests use `/sys/fs/bpf/unf/v12`.

## Consequences

The fixed egress state now has real kernel ownership, atomic activation,
capacity-failure rollback, restart reconstruction, and exact cleanup semantics.
A privileged kernel-map test proves partial insertion cannot displace the active
bank and that the pointer-selected bank reconstructs after userspace loss.
The repeatable gate is `make egress-dataplane-map-test`.

This decision does not claim a live controller endpoint, TC consumption,
steering, address ownership, NAT, or packet correctness. Those remain subsequent
Phase 8.5 gates.
