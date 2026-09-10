# ADR 0191: Proof-Carrying Deferred Encryption

- Status: Accepted and implemented for Phase 9.5ad
- Date: 2026-09-10

## Context

The controller, agent, Linux provider, route authority, and persistent eBPF
maps could produce one proven encryption generation, but TC deliberately did
not consume it. Selecting before policy or before Service translation would
either let encryption imply authorization or choose a tunnel for a virtual
frontend rather than its actual backend. Folding every concern into the main
classifier would also exceed a maintainable verifier boundary.

## Decision

UNF introduces **Proof-Carrying Deferred Encryption**:

- the policy classifiers can reach the encryption stage only after an allow;
  their CPU-local observation contains the final translated destination;
- family-specific tail programs isolate verifier complexity and run after
  explicit egress ownership. A missing tail program returns drop;
- one direct identity lookup serves single-Node destinations. Only an
  address-bound replicated identity performs the additional witnessed IPv4 or
  IPv6 LPM lookup;
- the active config, decision, path, transport, policy revision, Service
  revision, contract revision, key epoch, kernel/readiness digests, MTU, and
  mark lease must agree before TC changes metadata;
- new TCP state requires an initial SYN. A bounded LRU Causal Epoch Lease keeps
  an exact five-tuple on its admitted active or draining transport, while
  invalid, expired, removed, or revoked state is deleted and dropped;
- only UNF's leased mark field changes. Native or out-of-scope external traffic
  clears that field, and Required traffic never falls back to plaintext;
- DSR Required traffic currently drops because DSR's direct-neighbor redirect
  retains the VIP and would bypass the selected policy route. Phase 9.6 must
  supply a proven tunnel-aware DSR handoff before that composition is claimed.

This stage performs no cryptography. The kernel WireGuard interface selected
by the preinstalled masked policy rule remains the only encryption engine.

## Consequences

Packet work is constant for a direct identity and adds one LPM lookup only for
replicated identities. Userspace churn cannot invalidate an established epoch
lease silently, while map/config discontinuity denies instead of leaking
plaintext. Service selection remains independent from encryption authority.

## Verification

`make encryption-tc-consumer-test` inherits the complete Phase 9.5ac chain,
compiles the real BPF object, loads all ten programs through the kernel
verifier, executes IPv4 direct and IPv6 address-bound packets with
`BPF_PROG_TEST_RUN`, removes Required transport authority and observes
`TC_ACT_SHOT`, checks fixed-width predicates, and runs strict Clippy.
