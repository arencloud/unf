# ADR 0148: Require diversity-quorum evidence for egress reachability

**Status:** Accepted and implemented for Phase 8 milestone 8.8a

## Context

The existing provider-neutral gateway contract separates host readiness from
external reachability, but its first `static` adapter is intentionally only an
operator assertion. That is sufficient for development packet tests and safe
release ordering; it is not sufficient for production route authority. A BGP
speaker can acknowledge an update that no upstream router selected, multiple
observers can be replicas in one correlated failure domain, and one vantage can
hide a regional, VRF, or address-family failure.

Binding egress to one routing implementation would repeat a common CNI
limitation: policy, allocation, routing, and recovery would share one opaque
health signal. Counting unscoped pings or speaker sessions would be equally
unsafe because neither proves the exact externally visible path set.

## Decision

UNF introduces **Diversity-Quorum Reachability (DQR)** as the common evidence
contract for static/native, BGP, cloud, overlay, and future cross-cluster
adapters.

1. A canonical schema/algorithm-v1 plan binds the owner, provider, desired and
   allocation revisions, lease epoch, action, exact IPv4/IPv6 addresses,
   permitted gateway/forwarding identities, minimum and maximum path
   cardinality, required network vantages, and observation lifetime. A
   domain-separated SHA-256 digest seals the complete plan.
2. Each observer publishes a complete per-address route view for exactly one
   plan and vantage. Its identity, failure domain, source epoch/revision,
   observation interval, exact path set, and plan digest are independently
   sealed. Unknown paths and incomplete or noncanonical dual-stack views are
   rejected before assessment.
3. Authority counts distinct failure domains, not observer processes. Every
   required vantage must meet its configured diversity quorum. All fresh
   observers within a vantage must agree on the exact path set; disagreement is
   conflict evidence, not a majority election that could mask split routing.
4. An Ensure assessment becomes `Ready` only when every address at every
   vantage has an agreed permitted path count. A Withdraw assessment becomes
   `Withdrawn` only when the same complete diverse witness set observes an
   empty path set. Missing quorum, correlated-only replicas, disagreement,
   partial ECMP, unknown paths, and expired evidence produce `DenyClosed`.
5. Positive authority ends at the earliest observation validity or maximum-age
   deadline. The assessment records that absolute deadline and is independently
   replayable from its exact evidence set. Only the opaque verified-assessment
   type may reach the consumer deadline check, so a self-hashed claim cannot
   bypass evidence replay. It cannot remain ready merely because the controller
   or provider stopped updating it.

This is intentionally stricter than speaker/session health. It permits
different exact path sets at different declared vantages, which supports
regional routing and VRFs, while requiring agreement inside each vantage.

## Consequences

- A provider can mutate routes but cannot self-certify their externally visible
  result.
- Ten replicas in one rack or control plane count as one failure domain, so
  correlated deployment does not manufacture quorum.
- IPv4 and IPv6, ECMP cardinality, route domains, and regional visibility are
  explicit evidence rather than implicit backend behavior.
- Withdrawal becomes scoped positive evidence of absence, suitable for later
  Proof of Safe Forgetting integration; it is never inferred from timeout or
  provider disappearance.
- The contract adds no route mutation, observer transport, production BGP,
  BFD, graceful restart, cloud adapter, controller ingestion, dataplane expiry,
  Kind traffic, or OpenShift claim. Those require subsequent 8.8 slices.

## Verification

`make egress-reachability-contract-test` inherits the verified 8.7 lifecycle
and adds exact domain tests for dual-stack two-path ECMP across two vantages,
distinct-failure-domain quorum, correlated replica rejection, conflicting and
partial path denial, finite autonomous expiry semantics, complete diverse
withdrawal, foreign path rejection, digest mutation, deterministic replay, and
strict linting.
