# ADR 0221: Proof-Carrying Monotonic Retirement

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The mandatory fresh Kind run after ADR 0220 passed default-required,
selective-native, ciphertext, and fail-closed link-fault stages. During natural
rotation, the source Node durably journaled epoch 1 for retirement and activated
epoch 2. Some epoch-1 route state was already absent while the exact UNF owner
alias, local WireGuard identity, peer authority, and interface remained.

Retirement required a pristine snapshot before deleting the interface. That
condition can prove active readiness, but it is the wrong order relation for
teardown: an absent owned object is progress, not foreign authority. Every
retry therefore preserved the journal, the old key remained draining, the
two-epoch key authority stayed full, and the fleet could not converge on its
successor. Required traffic did not downgrade to plaintext, but recovery made
no progress.

## Decision

UNF introduces **Proof-Carrying Monotonic Retirement**. A digest-verified
retiring plan authorizes deletion when every object that still exists is within
that exact plan:

- interface name/index, versioned owner alias, local public key, listen port,
  fwmark, and MTU remain exact;
- every remaining peer key, endpoint, keepalive, and AllowedIP set exactly
  matches a planned peer;
- every remaining proof address is a planned address; and
- every remaining route has UNF's exact table, protocol, scope, output
  interface, and a prefix from the plan.

Planned peers, proof addresses, or routes may already be absent. Absence cannot
broaden authority and is therefore accepted during retirement. Any mutation,
duplicate, or addition is foreign state: UNF refuses deletion and preserves it
for diagnosis. Successful retirement still requires positive interface and
route-key absence before the durable journal or key epoch can be forgotten.

This is intentionally distinct from active-state repair. Active proof still
requires complete exact readback and recreates missing owned state; retirement
only moves downward through the authenticated ownership set.

## Consequences

- Restart, netlink teardown ordering, and external removal of an owned route or
  proof address cannot permanently consume the bounded two-epoch key window.
- UNF gains no broad cleanup authority and never adopts or deletes foreign
  peer, address, route, or same-name interface state.
- The check is bounded by the existing plan limits and uses indexed/sorted
  comparisons; it adds no packet-path work.
- Phase 9 remains incomplete until this runtime passes the full fresh Kind gate
  and independent digest-pinned OpenShift qualification.

## Verification

The privileged Linux kernel-provider test creates an exact dual-stack
WireGuard epoch, independently removes one plan-owned route and proof address,
proves pristine readback fails, and then requires monotonic retirement plus
positive interface/route absence. The same gate verifies same-name foreign
state is refused and preserved. `make encryption-kernel-provider-live-test`
executes the regression with real generic-netlink/rtnetlink and kernel
WireGuard. The complete `make encryption-composition-test` and fresh Phase 9
Kind gate remain the next acceptance levels.
