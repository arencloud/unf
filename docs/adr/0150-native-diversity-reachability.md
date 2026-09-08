# ADR 0150: Require independent diversity proof for the native provider

**Status:** Accepted and implemented for Phase 8 milestone 8.8c

## Context

The original `static` development adapter acknowledged its own Ensure and
Withdraw transactions. That was sufficient to exercise allocation, address
ownership, packet steering, NAT, and safe forgetting, but it was not evidence
that an external network could reach the address. A provider receipt has the
same limitation: the component that requested a route cannot independently
prove the route's effect, and a successful health endpoint can be stale, served
by the wrong Node, or reached through a path unrelated to the current lease.

The reference implementation needs to be operationally simple without creating
a weaker path that future BGP, cloud, or inter-cluster adapters could inherit.

## Decision

1. `native` is the live reference-provider name. The controller derives one
   cluster-scoped `EgressReachabilityPlan` from every exact native gateway
   desired record. Server-side apply owns its spec and labels; stable names bind
   the Kubernetes object owner UID, and a periodic exact-set reconciliation
   removes plans that no longer have a desired record. An independent monotonic
   plan generation permits quorum or freshness-contract migration without
   same-position mutation of an unchanged gateway desired revision.
2. Every native plan requires a `provider` vantage with one failure domain and
   a `fabric` vantage with two distinct failure domains. The provider receipt is
   visible and necessary, but it can never manufacture the independent fabric
   quorum that authorizes activation. Existing status-only Namespace-scoped
   observer RBAC and the durable 8.8b replay/persistence boundary are reused.
3. Expected forwarding identities are exact `native-node/<Node UID>` values.
   Minimum path cardinality is one and the maximum is the complete desired Node
   set, preserving a bounded route set for future ECMP without accepting a
   foreign gateway.
4. The agent exposes a schema-v1 `nonce-bound-kernel-ownership-v1` probe. A
   response is issued only when the requested address appears in the most recent
   gateway-address kernel readback. A domain-separated SHA-256 digest binds the
   DQR plan digest, desired revision, lease epoch, target address, 32-byte nonce,
   Node name/UID, agent Pod name/UID, and observation time. Verification enforces
   the expected challenge, gateway UID, mutation resistance, and a 30-second
   freshness bound.
5. The probe is deliberately non-authoritative. It is a bounded liveness and
   ownership primitive for observers, not a signature, provider receipt, or
   reachability acknowledgement. The development endpoint is plaintext because
   it must be reachable from an external qualification network; authenticated
   Kubernetes status publication plus DQR diversity remains the authority.
6. The portable IPv4 listener remains valid on IPv4-only hosts. When it is
   bound to the IPv4 wildcard, the agent also opens a separate IPv6-only socket
   on the same port when IPv6 is available. Failure to create that optional
   socket is explicit but does not break IPv4-only clusters; dual-stack gates
   require both `/32` and `/128` paths to exercise the same probe contract.
7. Legacy `static` self-acknowledgement remains only for compatibility with the
   earlier historical lifecycle gates. New examples use `native`. Production
   BGP and BFD are separate milestones and may not claim completion through this
   static-route reference adapter.

## Consequences

- Route mutation, kernel address ownership, external observation, durable
  decision, packet activation, and safe withdrawal are separately attributable.
- Replicating a provider process or a fabric observer inside one failure domain
  does not increase quorum. A wrong, missing, conflicting, expired, or foreign
  view denies closed and returns the managed source to its destination-preserving
  fence while unrelated native traffic remains unaffected.
- Positive withdrawal is observable work: external routes disappear first,
  every required vantage publishes a complete empty route set, and only then
  may the existing Proof of Safe Forgetting remove host addresses and reuse the
  allocation.
- The HTTP proof digest detects accidental or adversarial mutation but does not
  authenticate the server. Production deployments should place observer probes
  on protected networks or add an adapter-specific authenticated transport;
  neither changes the DQR authorization rule.

## Verification

`make egress-native-reachability-test` inherits the DQR contract and durable
lifecycle gates. Focused domain, agent, and controller tests cover exact probe
replay/freshness/mutation, address and Node ownership, bounded stable plan names,
plan translation, mandatory provider plus two-domain fabric quorum, dual-stack
deployment rendering, and strict linting.

The dedicated three-Node kube-proxy-free dual-stack Kind lifecycle uses one
provider fixture and two separately authorized fabric observers. It proves no
activation from address ownership, denial for a disagreeing view, live `/32`
and `/128` route and probe success, translated IPv4/IPv6 UDP traffic, controller
restart, autonomous evidence expiry and source fencing, higher-revision
recovery, agent restart/readback, explicit route removal, failed external
probes, diverse complete withdrawal observations, final safe release,
same-address higher-epoch reuse, and exact plan/observation/current-evidence
cleanup. Evidence is written to
`.artifacts/phase8-egress-native-reachability-kind.json`.
