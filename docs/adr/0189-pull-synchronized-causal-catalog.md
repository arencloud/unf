# ADR 0189: Pull-Synchronized Causal Catalog

- Status: Accepted and implemented for Phase 9.5ab
- Date: 2026-09-10

## Context

The placement projection and fleet forge are pure, but controller watches
advance independently. Rebuilding on every watch event creates transient cuts
and needless cryptographic/kernel churn; publishing an older catalog while a
new membership lacks keys can instead leak stale authority. Policy projection
also cannot enumerate all 65,536 ports per protocol and workload pair.

## Decision

UNF introduces the **Pull-Synchronized Causal Catalog**:

- the authenticated agent plan poll is the synchronization point; one mutex
  captures membership, Node UID/readiness, IPAM blocks, underlay addresses,
  workload placement/identity, policy, service, routing, egress, and complete
  public-key truth before any catalog publication;
- a source fingerprint binds all causal revisions and the public key-cut
  digest. Concurrent or repeated polls coalesce onto one generation, while any
  changed source produces exactly one monotonic successor;
- incomplete topology, key publication, or mutual attestation returns no plan,
  and an invalid complete cut fails closed instead of serving the prior cut;
- policy demand uses a discontinuity-complete quotient: every supported
  protocol is evaluated at numeric rules, named-port values, range edges and
  their adjacent classes, plus concrete dual-stack source/destination
  addresses. Ingress and egress must both allow a class before it can request
  transport;
- the fleet cut is published atomically and only then sealed to the requesting
  current Pod, Node name, Node UID, predecessor, and nonce.

This is intentionally pull-synchronized, not poll-derived authority: all input
remains controller-observed Kubernetes truth, and polling only asks the
controller to materialize the latest stable quotient.

## Consequences

The design removes per-event plan churn without adding a debounce window,
retains exact policy provenance, and reduces the port domain to its semantic
boundaries without approximation. A plan remains public desired input; private
keys, kernel convergence, route proof, and BPF activation stay Node-local.

## Verification

`make encryption-controller-plan-test` inherits the complete Phase 9 chain and
proves pre-initialization absence, authenticated Node/UID scoping, a real
key-ready projection, atomic dormant-plan publication, retry coalescing, causal
successor generation, key lifecycle behavior, and strict Clippy.
