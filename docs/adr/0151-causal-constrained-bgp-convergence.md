# ADR 0151: Bind BGP convergence to causal route identity

**Status:** Accepted and implemented for Phase 8 milestone 8.8d

## Context

A routing daemon accepting an API request does not prove that a route reached
its Adj-RIB-Out, an external router, or a sufficiently independent part of the
fabric. An ordinary prefix and next hop also cannot distinguish the current
allocation from a stale advertisement after the same egress address is reused.
Blindly replacing a whole routing configuration makes rollback unnecessarily
broad, while writing a new BGP implementation would add protocol risk unrelated
to UNF's identity, lease, and evidence model.

UNF needs a production routing protocol adapter without allowing daemon health,
one peer, or one observer replica to self-certify reachability.

## Decision

1. UNF integrates GoBGP v4.9.0 through its typed gRPC API. The adapter vendors
   the six unmodified upstream protocol files from commit
   `01c5c4c27f9a1ac3b5927f433b5115f9b0eee791`; UNF does not implement BGP
   packet parsing or its state machine. FRR remains a valid future adapter, but
   its current gRPC surface is documented as experimental and `bgpd` is not yet
   converted to its management daemon. GoBGP provides the typed path, peer,
   multipath, policy, and graceful-restart surfaces required here.
2. Node-local configuration is canonical, digest-sealed, and bounded. It fixes
   the local ASN/router ID, family-specific next hops, at most 64 peers, exact
   AFIs, peer/failure-domain identity, received-prefix limits, multipath limit,
   graceful-restart deadlines, maximum total routes, maximum changed routes,
   and a default-deny export-prefix envelope. Single-hop peers use GTSM. A
   foreign peer at an intended address or global ASN/router-ID drift fails
   closed; reconciliation only replaces peers marked `unf/egress-bgp/*`.
3. Every host route carries a Causal Route Capsule (CRC) by default. Three
   transitive BGP large communities contain a schema marker and a 128-bit,
   domain-separated fingerprint of the exact intent owner, provider, desired
   revision, lease epoch, prefix, next hop, gateway UID, and DQR plan digest.
   Consequently, a stale route for a reused IP cannot impersonate the current
   lease even when its prefix and apparent topology are identical.
4. Route state changes are complete, bounded transactions. The canonical delta
   retains the full prior snapshot, rejects cross-owner/epoch replacement of
   the same prefix, and limits changed and total prefixes independently.
   Success requires exact local-RIB and every family-relevant Adj-RIB-Out
   readback. Failure restores only additions and withdrawals in that
   transaction. A persistence failure invokes the same scoped rollback.
5. Controller-owned BGP DQR plans require one `adj-rib-out` failure domain and
   two independent `fabric` failure domains. Expected forwarding identities are
   exact `bgp-node/<Node UID>` values. The controller materializes and garbage
   collects the plans, while an authenticated agent can fetch only plans whose
   desired gateway set contains its exact Node name and UID.
6. The agent derives routes from the admitted local gateway projection and the
   full controller plan, then reconciles the local GoBGP speaker, applies and
   reads back the route transaction, and durably commits its complete snapshot.
   On an unchanged revision it still verifies and replays the durable snapshot,
   allowing recovery after a daemon restart without treating the checkpoint as
   proof that the live RIB exists.
7. Positive authority remains finite DQR evidence. Neither GoBGP process health,
   peer establishment, local-RIB presence, nor an Adj-RIB-Out receipt can replace
   two agreeing fabric failure domains. BFD is a separate correlated-liveness
   input in milestone 8.8e and cannot become ownership evidence.

## Consequences

- Routing protocol correctness stays with an evaluated upstream stack, while
  UNF owns identity, lease fencing, default-deny policy, transactional bounds,
  causal attribution, and independent reachability authority.
- The CRC makes route telemetry useful during reuse and recovery: observers can
  explain which owner, epoch, gateway, and proof plan a route represents rather
  than inferring identity from an IP address.
- Multi-AFI negotiation works over a bounded peer session, and two gateways can
  advertise independent next hops for ECMP without an all-Node BGP mesh.
- BGP configuration remains explicit node-local input. Dynamic BGP configuration
  APIs, TCP-AO/MD5 secret delivery, BFD, EVPN, large-scale qualification, and
  OpenShift qualification are not implied by this milestone.

## Verification

`make egress-bgp-test` inherits the complete native/DQR safety chain, builds the
pinned GoBGP image, runs domain/controller/agent/adapter tests and strict Clippy,
and executes `hack/verify-egress-bgp.sh`.

The live gate creates four GoBGP speakers on an isolated dual-stack network: two
UNF gateways and two external fabric failure domains. It establishes all bounded
sessions, advertises exact IPv4 and IPv6 host routes from both gateways, verifies
both CRC-bearing paths independently in both external global RIBs, rejects a
stale capsule, and compiles the real views to finite DQR Ready authority. It then
proves single-path withdrawal, scoped rollback, complete withdrawal, durable
RIB reconstruction, repeated exact withdrawal, and fixture cleanup.

GoBGP evaluation references: [project](https://github.com/osrg/gobgp),
[gRPC API](https://github.com/osrg/gobgp/blob/master/docs/sources/grpc-client.md),
[routing policy](https://github.com/osrg/gobgp/blob/master/docs/sources/policy.md),
and [graceful restart](https://github.com/osrg/gobgp/blob/master/docs/sources/graceful-restart.md).
The FRR comparison uses its [official gRPC status](https://docs.frrouting.org/en/latest/grpc.html).
