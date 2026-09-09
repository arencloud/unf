# ADR 0174: Proof-Carrying Linux Convergence Capsule

- Status: Accepted and implemented for Phase 9.5m
- Date: 2026-09-09

## Context

Phase 9.5l makes proposal, controller admission, route proof, and map activation
different consuming capabilities. The remaining local boundary must use the
real Linux providers without turning an intermediate interface, recovered
file, or partially installed policy rule into packet authority.

Multi-epoch convergence also cannot depend on input order. Kubernetes watches,
kernel dumps, and restart recovery may present the same complete set in a
different order. Rewriting already exact interfaces because their observations
arrived differently would create avoidable churn during rotation.

## Decision

Phase 9.5m introduces the **Proof-Carrying Linux Convergence Capsule**.

`LinuxPreparedLocalGeneration::stage_linux` follows one bounded sequence:

1. replay the complete map checkpoint and proposed generation before mutation;
2. preflight every plan, unique epoch/interface, recipient Node UID, and exact
   fast-path transport relationship;
3. admit private-key access only when cluster, Node UID, epoch, public key, and
   locally ready key phase all match;
4. stage plans in canonical epoch/interface order through the real
   `LinuxWireGuardProvider`, accepting already-exact state without churn;
5. independently join the complete, permutation-independent kernel readback
   cut to every fast-path configuration digest;
6. derive exact policy-route authority and a domain-separated convergence
   witness, then expose only the retryable secret-free Node fact;
7. require the controller to return that exact fact before the real
   `LinuxEncryptionRouteProvider` can mint a consuming permit; and
8. pass the resulting latch to the agent's existing proof-carrying Aya map
   transaction adapter.

The capsule itself is neither cloneable nor serializable. Its compact witness
is diagnostic provenance, not authority. Private keys remain inside
`unf-encryption` and are borrowed only at the Linux provider call.

This design is a self-validating convergence algorithm: each side effect is
followed by exact readback that becomes an input to the next typed stage.
Equivalent input permutations produce one witness. Partial evidence never
does.

## Failure and recovery

All checkpoint, plan, and key relationships that can be checked without the
kernel are checked before the first mutation. A failed fresh interface is
rolled back by the provider with positive absence. If a later epoch fails, an
earlier exact interface remains inactive and is reused on retry. If policy-rule
activation succeeds but map publication fails, the old map generation cannot
emit the new selector, so the rules are inert and exact replay can continue.

Foreign links, routes, rules, keys, Node identities, active-before-publication
plans, missing readback, duplicate commitments, and digest substitutions fail
closed.

## Consequences

- Rotation convergence is deterministic and avoids unnecessary kernel churn.
- A serialized checkpoint, controller response, or diagnostic witness cannot
  independently activate Linux or Aya state.
- The concrete Linux providers and Aya adapter now share one typed activation
  path instead of relying on boolean readiness flags.
- This slice does not yet make the running agent produce plans or submit facts,
  does not remove startup revalidation quarantine, and makes no TC or encrypted
  packet claim. Those runtime-loop and packet-consumer slices remain next.

## Verification

`make encryption-linux-convergence-test` inherits every earlier Phase 9.5 gate,
then verifies ready-key confinement, exact and permutation-independent
multi-epoch joins, partial/foreign/active-stage refusal, real Linux provider
call ordering, the agent Aya adapter boundary, and strict Clippy.
