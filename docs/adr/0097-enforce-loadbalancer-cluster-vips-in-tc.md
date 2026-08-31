# ADR 0097: Enforce LoadBalancer Cluster VIPs in TC

**Status:** Accepted and implemented for Phase 6.5 (2026-08-31)

## Context

Phase 6.4 activated independently banked VIP state but intentionally left it
unconsumed. A packet implementation must not confuse allocation with
reachability, observe a VIP from a different Service bank, overwrite a reverse
tuple during source-port collision, or publish success before a release eBPF
object has passed the kernel verifier. It must also preserve the already
verified ClusterIP and NodePort paths.

## Decision

- New-flow lookup remains deterministic: ClusterIP first, then NodePort, then
  LoadBalancer VIP. A VIP is eligible only when active Service, reachability,
  allocation, bank, family, port, protocol, schema, and revision fields form one
  exact coherent tuple. A matched malformed frontend fails closed and emits
  bounded invalid-frontend provenance.
- `externalTrafficPolicy: Cluster` selects from the referenced Service bank,
  translates the VIP and Service port to the chosen backend tuple, and source
  translates to the VIP plus a bounded dynamic port. The paired connection
  restores the VIP/Service port and original external client on reverse traffic.
- Source-port allocation reuses the full-range dispersed algorithm from ADR
  0091 with 16 verifier-bounded attempts. Pair insertion is all-or-nothing;
  collision exhaustion drops with explicit provenance instead of replacing an
  existing reverse tuple.
- The existing connection value layout is unchanged. The Cluster source-NAT
  flag retains the translation mechanics, while one reserved byte classifies
  LoadBalancer provenance. Existing validated pairs continue through backend
  and active-bank churn; new flows use only the current coherent banks.
- DNAT and backend selection happen before ingress policy evaluation, so policy
  sees the original external source and translated backend identity and port.
  Activating an empty VIP bank stops new interception before provider route and
  Kubernetes publication withdrawal.
- VIP source translation in this milestone is qualified for the bounded
  `DirectNode`/static-route provider model: the same Node owns the VIP and its
  reverse connection state. ECMP, anycast across Nodes, and distributed
  connection-state recovery remain explicit Phase 6 exclusions and cannot be
  inferred from this gate.

## Consequences

IPv4 and IPv6 TCP/UDP LoadBalancer Cluster traffic now has exact forward and
reverse semantics without changing persistent ABI v6. Service events distinguish
LoadBalancer Cluster from ClusterIP and NodePort while retaining fixed-size,
bounded fields. Transactional map activation and withdrawal decide admission of
new flows; compatible connection entries retain established traffic.

The 16-attempt allocator is deliberately bounded for verifier and latency
safety. Exhaustion fails closed. Production-scale source-port capacity, ECMP,
DSR, and multi-Node state distribution require separate designs and evidence.
Kubernetes status publication is still withheld until operations, Kind, and
OpenShift qualification close their independent gates.

## Verification

`make loadbalancer-cluster-dataplane-test` inherits the complete schema,
allocation, distribution, and transactional-host-state gates, runs strict
Clippy, builds the release BPF object, and loads it through the real kernel
verifier. Its packet execution proves IPv4/IPv6 TCP/UDP translation and reverse
restoration, deliberate source-port collision, established-flow retention
through backend churn, backendless drop, unrelated pass-through,
translated-backend ingress-policy denial, empty-bank withdrawal, and bounded
LoadBalancer event classification. The same release object reruns the full
NodePort Cluster/Local and ClusterIP packet suites as regression evidence.
