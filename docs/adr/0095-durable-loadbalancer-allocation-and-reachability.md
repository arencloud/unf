# ADR 0095: Separate durable VIP allocation from reachability convergence

**Status:** Accepted and implemented for Phase 6.3 (2026-08-31)

## Context

An admitted LoadBalancer Service does not yet own an address, and an allocated
address is not proof that traffic can reach a ready dataplane. Kubernetes
status and finalizers add a fourth ownership surface whose foreign entries must
survive retries, controller restarts, and deletion. Treating any one of these
surfaces as evidence for the others would publish an externally visible promise
before the fabric can satisfy it.

The first qualification provider also needs a bounded implementation that can
exercise the contract without claiming production BGP, L2, EVPN, or cloud load
balancing.

## Decision

The new `unf-loadbalancer` crate owns provider-neutral control-plane state and
has no Kubernetes, host, or packet-path side effects.

- Canonical, non-overlapping IPv4/IPv6 pools carry immutable pool UID and exact
  provider name, instance, and mode.
- A lease binds the schema-v3 Service ID, namespace, name, Kubernetes UID,
  family/requested-address intent, pool provenance, intent revision, and an
  independently advancing allocation revision.
- Allocation chooses the lowest free usable address per family within a fixed
  scan bound. Requested collisions, exhaustion, pool drift, replay mutation,
  and corrupt checkpoints fail atomically. Exact replay is stable; release is
  exact and reusable.
- The first bounded provider is `DirectNode`: every active VIP is desired on
  every selected Node. The complete target cross-product, provider provenance,
  source epoch, allocation revision, and reachability revision are validated.
  An acknowledgement converges only the exact desired revision. An empty newer
  snapshot represents explicit withdrawal.
- Only `network.unf.io/load-balancer` schema-v3 intent becomes an allocation
  request. Classless, foreign-class, and non-LoadBalancer Services remain
  outside UNF ownership.
- Publication is a one-action state machine. Active Services acquire the exact
  UNF finalizer, allocation, reachability readiness, and dataplane readiness in
  order before status publication. Deletion clears UNF-owned status, withdraws
  reachability, removes dataplane state, releases the lease, and only then
  removes the finalizer.
- Status reconciliation removes only IPs recorded as previously UNF-owned,
  preserves foreign IP and hostname entries byte-for-byte, and rejects an
  attempted adoption collision. Finalizer reconciliation changes only the
  exact UNF finalizer.

The control-plane types serialize with strict schema versions. Kubernetes
ConfigMap persistence and authenticated distribution may store these exact
documents, but cannot infer readiness or rewrite their ownership fields.

## Consequences

- Controller restart can restore exact allocation provenance without scanning
  Service status or adopting a foreign address.
- Reachability and dataplane consumers can advance independently, while status
  remains fail closed until both acknowledge the admitted revision.
- Direct-Node provides a finite qualification target but does not claim that
  external routing has been installed. Live delivery begins with the compatible
  distribution and transactional host-state milestone.
- Production routing/cloud providers, host state, eBPF translation, health
  checks, and live Kubernetes publication remain later Phase 6 gates.

## Verification

`make loadbalancer-control-plane-test` runs the schema-v3 prerequisite, then
tests canonical pool admission, deterministic dual-stack allocation,
requested-IP conflict and bounded exhaustion, immutable provenance, exact
replay/revision/release/reuse, strict checkpoint restore, complete DirectNode
target construction, stale acknowledgement rejection, explicit withdrawal,
Service-class admission, finalizer/status preservation, publication gating and
ordered deletion, plus strict Clippy.
