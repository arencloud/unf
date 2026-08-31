# ADR 0098: Enforce LoadBalancer Local policy, source ranges, and health

**Status:** Accepted and implemented for Phase 6.6 (2026-08-31)

## Context

The Phase 6.5 Cluster VIP path could select any ready backend and source
translate external clients to the VIP. `externalTrafficPolicy: Local` has a
different contract: the receiving Node may select only its own ready,
non-terminating endpoints and must preserve the client source. Kubernetes
source ranges and `healthCheckNodePort` must follow that same current local
placement without weakening the coherent Service/reachability/allocation
transaction or changing the qualified ClusterIP and NodePort paths.

## Decision

- The service compiler places each Node's Local LoadBalancer backend membership
  in a deterministic, disjoint frontend-index namespace in the existing
  transactional `SERVICE_BACKEND_SLOTS` bank. The VIP frontend references only
  the receiving Node's slots. No eligible local endpoint gives an exact
  zero-backend frontend and a fail-closed new-flow drop; it never falls back to
  a remote backend.
- A Local VIP performs only destination translation. Forward packets retain the
  external client address and port; the paired connection restores the VIP and
  Service port on reverse packets. Existing valid pairs retain their selected
  backend across desired-state churn, while fresh flows use current placement.
- A frontend with `loadBalancerSourceRanges` performs a longest-prefix lookup
  scoped by Service ID and active VIP bank before backend selection. IPv4 and
  IPv6 entries bind the exact Service, reachability, allocation, schema, and
  bank tuple. A miss drops with bounded `source-range-denied` provenance.
- Source-range tries are runtime maps reconstructed from the authenticated
  owner-only Service and reachability checkpoints before TC attachment. They
  are intentionally not added to persistent ABI v6's exact 24-map ownership
  set. Both tries stage, read back, roll back, switch, clear, and reconstruct
  with the VIP transaction; malformed or stale tuples fail closed.
- For every admitted Local Service with `healthCheckNodePort`, the agent owns
  one dual-stack wildcard TCP listener on that exact port. `GET /healthz`
  returns JSON containing `localEndpoints`, with HTTP 200 when at least one
  referenced backend is ready, non-terminating, and local, and HTTP 503 when
  none is. Duplicate port ownership or a bind failure rejects reconciliation.
  Listener binds are staged before mutation, counts update atomically, failed
  tasks are recreated, and withdrawn intent closes the listener.
- Health is a Node-local dataplane signal, not external advertisement or
  Kubernetes status publication. Publication remains gated by the operations
  and platform milestones.

## Consequences

Dual-stack TCP/UDP Local VIPs preserve the real client tuple, enforce exact
source CIDRs, and expose placement-sensitive health without widening persistent
map ownership or silently selecting a remote endpoint. The design preserves
the existing verifier-bounded connection and event layouts. It does not claim
active application probing, distributed connection state, ECMP/anycast Local
delivery, SCTP, DSR, or production health-server hardening beyond the bounded
Kubernetes contract.

## Verification

`make loadbalancer-local-dataplane-test` inherits the complete Phase 6 schema,
allocation, host-state, and Cluster VIP gates. It runs exact compiler and
dual-stack health lifecycle tests, strict Clippy, builds the release BPF object,
loads it through the real kernel verifier, and executes IPv4/IPv6 TCP/UDP Local
packets. The packet gate proves source preservation and reverse restoration,
CIDR allow/deny, no-local-backend drop, remote/unready placement transitions,
recovery, translated-backend ingress-policy ordering, bounded event reasons,
and runtime source-trie reconstruction. The inherited gate reruns the complete
LoadBalancer Cluster, NodePort Cluster/Local, and ClusterIP packet regressions
against the same implementation.
