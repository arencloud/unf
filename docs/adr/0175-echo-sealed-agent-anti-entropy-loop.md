# ADR 0175: Echo-Sealed Agent Anti-Entropy Loop

- Status: Accepted and implemented for Phase 9.5n
- Date: 2026-09-09

## Context

Phase 9.5m can produce a non-serializable Node-local capability only after real
WireGuard staging and complete kernel readback. The controller already accepts
its secret-free fact and publishes only a complete fleet cut, but the agent's
periodic loop still pulled desired generations without requiring that local
capability. A valid controller response was nonce- and predecessor-bound, yet
it did not prove that this Node had proposed the byte-exact checkpoint.

That asymmetry is unsafe for a universal fabric: a controller must coordinate
agreement, not manufacture Node-local kernel truth.

## Decision

Phase 9.5n introduces the **Echo-Sealed Agent Anti-Entropy Loop**.

The running agent owns at most one volatile `LinuxPreparedLocalGeneration`.
It refuses cross-Node or wrong-predecessor proposals and cannot replace a
different in-flight capability. With no prepared capability, the default loop
does not contact either generation endpoint.

For every retry the agent performs this strict sequence:

1. independently replay the locally prepared fact;
2. submit it through the existing Pod-bound bearer/TLS endpoint and require
   exactly `202 Accepted`;
3. issue a fresh OS-CSPRNG nonce bound to the durable predecessor;
4. poll the Node-sealed generation endpoint;
5. retain the same local capability on transport failure, rejection, or `204`;
6. accept only a cryptographically valid capsule whose recipient and complete
   nested checkpoint byte-exactly echo the local fact; and
7. atomically persist that admission before advancing the in-memory cursor.

After exact admission, the non-serializable capability remains volatile in a
distinct controller-admitted state. Serialized desired state is still not map,
route, TC, or packet authority.

## Consequences

- Compromise or defects in generation selection cannot substitute a different
  checkpoint after a Node has reported local convergence.
- Retries are naturally idempotent and do not mint, clone, or discard local
  activation authority.
- An unavailable or incomplete fleet delays publication without weakening to
  controller-only truth or plaintext fallback.
- The loop is enabled by default but intentionally idle until the local plan
  producer offers a fully proven capability.
- Consuming the admitted capability into policy routes/Aya maps, reconstructing
  proof after restart, and releasing TC quarantine remain the next milestone.

## Verification

`make encryption-agent-anti-entropy-test` inherits the full Phase 9.5m gate,
checks the fact-before-pull and exact-echo source invariants, exercises
substitution and no-local-proof refusal, and applies strict Clippy to the
encryption domain and agent.
