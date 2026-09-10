# ADR 0192: Flow-Adaptive Secure DSR

- Status: Accepted and implemented for Phase 9.5ae
- Date: 2026-09-10

## Context

LoadBalancer DSR deliberately retains the virtual IP in the packet and sends
it directly toward the selected backend. WireGuard, however, chooses a peer
from the inner destination's `AllowedIPs`. Marking a VIP-only DSR packet would
therefore bypass or fail peer selection; treating that mark as encrypted would
be a security defect. Disabling DSR cluster-wide would discard a valuable fast
path for Native flows.

## Decision

UNF introduces **Flow-Adaptive Secure DSR**:

- Service selection and policy still run once against the exact selected
  backend. Encryption never reselects a backend;
- Native flows retain the existing VIP-preserving direct-return DSR path;
- when that exact flow resolves to Required encryption, a dedicated verifier
  tail program converts only its already-created forward DSR state into an
  atomic forward/reverse NAT pair, rewrites the inner destination to the
  selected backend, and retains source identity/address;
- runtime `SERVICE_CONNECTION_FLAG_ENCRYPTED_NAT` distinguishes the transition
  from frontend intent. It is valid only for cluster LoadBalancer provenance
  and cannot combine with DSR, NodePort Cluster, or NodePort Local flags;
- the return hook restores the Service VIP from the reverse pair. Failure to
  create both records or rewrite the packet drops and removes the pair;
- explicit egress ownership runs before encryption. External egress redirects
  cannot borrow a Pod transport or create a Causal Epoch Lease;
- established Required flows may use a draining epoch only until its deadline;
  new flows cannot enter it, and transport removal revokes existing leases
  without plaintext fallback.

This is a per-flow semantic morph, not a global mode downgrade. It preserves
DSR where compatible and automatically selects the reversible shape demanded
by encrypted inner routing.

## Consequences

Users do not need separate encrypted and unencrypted Services. The dataplane
avoids a second backend selection and adds the secure-NAT work only to Required
DSR flows. External egress remains independently owned, and all failure paths
are deny-only.

## Verification

`make encryption-composition-test` inherits the complete 9.5ad gate, loads the
real BPF object, and executes dual-stack encryption, egress, rotation,
revocation, and LoadBalancer DSR packet tests. It proves Native VIP
preservation, Required backend rewrite plus reverse VIP restoration, exact
two-record provenance, egress-before-encryption ordering, and strict Clippy.
