# ADR 0126: Activate destination-exact policy-first source steering

**Status:** Accepted and implemented for the Phase 8.5 source-steering slice

## Context

The first egress map ABI selected an identity and candidates but did not encode
the intent's destination constraints. Consuming that state would have steered
every destination of a selected identity, including traffic outside a
target-specific intent. Source application acknowledgements also prove map
commit, not that a path certificate exists or that packet steering is safe.

## Decision

Egress map ABI v2 adds independently banked IPv4 and IPv6 LPM destination
tables. Every key starts with an exact intent index and bank discriminator, then
the canonical network bits. `Any` is represented by one per-family prefix under
that discriminator; it is never a global trie wildcard. Values repeat the
contract revision and intent digest. Fenced as well as active sources receive
their destination entries so an exact managed target drops during preparation
without capturing unrelated native egress.

The source workload-veth ingress classifier evaluates the existing bilateral
NetworkPolicy decision first. A denial terminates processing. ClusterIP,
NodePort, and LoadBalancer translations stay on their service path and are not
captured by broad egress intent. For a non-service TCP/UDP flow, absence of an
active source or destination match preserves native routing. Once both match,
fenced admission, policy-revision skew, unsupported tunnel mode, missing or
malformed destination/selection/address/path state, lease or contract skew,
invalid family data, and MTU overflow all drop.

An active exact match hashes the original tuple into the userspace-compiled
251-bucket table, validates the selected address and direct-neighbor path, and
hands the unchanged packet to the kernel neighbor subsystem on the certified
interface and next hop. No source translation is performed in this slice. A
per-CPU steering workspace keeps the complete validation chain within verifier
stack bounds without weakening any checks.

Adding two durable maps and changing the egress config meaning is an intentional
persistent BPF-state transition. ABI v13 is the exact 33-map current boundary;
ABI v12 remains an exact historical 31-map cleanup boundary and is never
adopted as partial v13 state.

## Consequences

An egress identity can no longer be activated from identity-only state, and
target-specific intent cannot capture an unrelated destination. The real-kernel
gate proves verifier admission, IPv4 and IPv6 prefix matches, unchanged-tuple
redirect, native nonmatches, fenced drops, and policy-denial precedence.

Live source synchronization deliberately still installs only fences because
route/path acquisition and readiness-driven `Active` transition are not yet
wired. Gateway address ownership, collision-safe SNAT/reverse state, standby
failover, egress events, and platform traffic remain later gates; this ADR does
not claim them.

`make egress-source-steering-test` inherits all prior Phase 8 gates, validates
the compiler and ABI-v13 map transaction, and runs the ignored privileged TC
packet test against the host kernel.
