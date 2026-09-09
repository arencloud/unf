# ADR 0166: Cooperative Route-Mark Lease

**Status:** Accepted and implemented for Phase 9.5e

## Context

The fast-path transport record contains the `fwmark` independently read back
from a kernel `WireGuard` interface. That mark belongs to the encrypted outer
UDP packet and prevents recursive routing. Copying it onto an inner workload
packet would collapse two different authorities into one routing class and can
create a tunnel loop. Replacing all of `skb->mark` would also corrupt metadata
owned by Services, applications, or another cooperating dataplane.

## Decision

UNF introduces a **Cooperative Route-Mark Lease**. Only bits 8 through 23
(`0x00ffff00`) belong to encryption route selection. The upper and lower eight
bits remain untouched, including the existing UNF Service DSR handoff bit.

The kernel-provider outer mark must be nonzero, entirely inside that owned
field, and not consume the complete field. The plaintext route selector is its
bitwise complement inside the same mask:

```text
route_mark = (!outer_fwmark) & 0x00ffff00
```

This is an O(1) bijection over every admitted value. Consequently, an inner
selector can never equal its outer bypass mark, no extra packet map lookup is
needed, and different admitted outer marks cannot alias. Fast-path compilation
also rejects one derived selector mapped to conflicting route tables. Applying
or clearing a lease changes only the owned field; a drop publishes no mark.

The packet decision now returns the outer evidence, derived route mark, exact
mask, route table, interface, MTU, and Causal Epoch Lease separately. Native
selection releases only the route-mark field. Required selection remains
fail-closed on policy, revision, authority, epoch, readiness, or drain failure.

## Consequences

UNF can coexist with other mark users without a cluster-wide mark takeover,
while masked policy rules can distinguish plaintext route selection from
`WireGuard` outer packets by construction. The 16-bit field admits far more
selectors than the bounded 4,096 transport map and the transformation adds no
hashing, allocation, or extra map access to the future packet path.

This milestone defines and enforces the shared mark contract but deliberately
does not mutate packets or install policy rules. Controller distribution must
allocate compatible outer marks, the agent must atomically install the matching
masked rule/table before publishing a generation, and the TC consumer must
apply the returned lease only after policy plus Service/egress resolution.

## Verification

`make encryption-route-mark-contract-test` inherits the complete Phase 9.5d
transaction gate, exhaustively checks all 65,534 admitted 16-bit values for
collision freedom, proves neighboring-bit preservation and exact release,
checks active fast-path output, rebuilds the real eBPF object, and applies
strict Clippy to the shared ABI, encryption domain, and agent adapter.
