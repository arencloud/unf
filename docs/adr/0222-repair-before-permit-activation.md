# ADR 0222: Repair-Before-Permit Activation

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The clean Phase 9 Kind qualification deliberately lowered every owned
WireGuard link on the source Node while rotation was live. Linux withdrew the
connected routes for both the active and prepared epochs. UNF retained the
interfaces, authenticated plans, keys, controller admission, and last-known-
good active packet authority.

ADR 0218 already defined exact-plan kernel self-healing, but the activation
sequence first asked Route-Before-Authority to verify the missing routes and
mint a permit. That correctly failed closed. Because the repair call followed
the permit call, the error returned before repair was reachable on every retry.
The source could not participate in the successor duplex proof, while its peer
timed out waiting at the rendezvous.

## Decision

Activation now follows a strict **Repair-Before-Permit** proof order:

1. consume no packet authority and retain the active predecessor;
2. replay only the admitted, digest-verified Node-local recovery plan using its
   matching private key;
3. independently require exact interface, peer, address, and route readback;
4. mint the generation-bound Route-Before-Authority permit from that exact
   repaired state;
5. execute the two-ended encrypted path proof; and
6. consume the existing activation latch only after every proof agrees.

Repair remains bounded and ownership-scoped. A foreign alias, local key,
endpoint, AllowedIP, route key, or plan/private-key mismatch stops activation
without map publication or plaintext downgrade. Already-exact state replays
idempotently.

## Consequences

- Link faults can no longer make their own existing self-healer unreachable.
- Permit issuance always observes the post-repair exact state in the same
  activation attempt.
- The change adds no BPF lookup, packet-path branch, tunnel, or key copy.
- Phase 9 remains incomplete until a fresh full Kind run and independent
  digest-pinned OpenShift gate pass.

## Verification

The static kernel-provider gate enforces source-order repair before permit. The
privileged provider test proves missing dual-stack route/address state is
restored only from the exact durable plan and that foreign state is preserved.
The complete Kind gate supplies the acceptance regression by lowering live
links during rotation, requiring Required denial plus Native continuity during
the fault, then requiring automatic route repair, duplex proof, rotation,
agent/controller recovery, and convergence.
