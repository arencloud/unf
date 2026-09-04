# Phase 8 identity-aware egress-fabric execution plan

Last reviewed: **2026-09-04**

Phase 8 implements master-prompt §24 as a provider-neutral enterprise egress
fabric. It builds on the verified source-side NetworkPolicy egress engine and
primary CNI, but treats external address ownership, gateway placement, steering,
NAT, reachability, and failover as separately revisioned domains. The
authoritative state remains in [project-status.md](../project-status.md).

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 8.1 | Architecture and acceptance boundary | **Verified** | ADR 0113 fixes explicit ownership, policy-before-steering precedence, an independently verified Egress Behavior Contract, lease-fenced gateway epochs, deterministic placement/failover, provider boundaries, compatibility, recovery, platform gates, and exclusions; `make egress-fabric-boundary-test` prevents drift |
| 8.2 | Egress intent, pool, and compatibility model | **Verified** | `unf-egress` provides bounded canonical Namespace/workload/ServiceAccount selectors, destinations, dual-stack non-overlapping pools, pool or explicit-address requests, deterministic complete-model validation, and strict ownership. The controller translates OpenShift `k8s.ovn.org/v1` EgressIP into the same intent, defaults/intersects selectors exactly, and preserves foreign status; `make egress-intent-test`; ADR 0114 |
| 8.2a | Egress Behavior Contract and reference validator | **Verified** | Schema-v1 exact-Node plans bind selected source identity, original destinations, policy allow, exact pool/explicit allocation, lease-fenced ready/reachable ranked gateways, derived capabilities, and six independent revision domains. Independent replay, domain-separated SHA-256 digests, 16-byte witnesses, and bounded explicit single-gateway failure envelopes pass `make egress-contract-test`; ADR 0115 |
| 8.3 | Durable allocation and gateway-provider contract | **Verified** | Schema-v1 allocation atomically assigns conflict-safe multiple IPv4/IPv6 addresses with exact owner/pool/provider provenance, bounded exhaustion, monotonic revisions/lease epochs, release/reuse, and strict checkpoint replay. Separate gateway/reachability provider interfaces, desired/ack revisions, epoch/address fencing, dual acknowledgement, safe withdrawal, and direct contract-fact projection pass `make egress-allocation-test`; ADR 0116 |
| 8.4 | Transactional distribution and gateway host state | **Verified** | Schema-v1 projection binds the existing authenticated Pod/Node principal, negotiates exact contract/host capabilities, independently replays all facts, and fences last-known-good epochs/revisions. Separate userspace ABI-v1 host banks commit through stage/readback/prepare/activate, pointer rollback, exact current/pending recovery, cold reconstruction, and version-scoped cleanup; `make egress-host-state-test`; ADR 0117 |
| 8.4a | Egress Proof Chain and zero-leak admission | **Verified** | Default `Native -> Fenced -> Active` admission prevents explicit-intent convergence/withdrawal leaks. Domain-separated rendezvous hashing deterministically selects same-family multiple addresses and ready gateways; a versioned proof binds the authoritative identity, original tuple, exact contract/revisions, lease, choice, and witness for independent selected-gateway replay. Ten adversarial tests and strict Clippy pass `make egress-proof-test`; ADR 0118 |
| 8.5 | Live distribution, source steering, and gateway NAT dataplane | **Verified** | The controller joins watched Pods, identities, NetworkPolicy, intent, allocation, explicit Ready gateway, and reachability into exact source-Node contracts, then invalidates stale distributions transactionally. Egress ABI v3 and persistent ABI v14 provide policy-first steering, collision-safe dual-stack gateway SNAT/reverse state, sparse proof-bound witnesses, and Proof of Safe Forgetting. Node-UID-bound `/32`/`/128` ownership now publishes exact proxy-NDP state on the IPv6 uplink. `make egress-kind-lifecycle-test` inherits every focused 8.5 gate and proves watched intent, bilateral activation, translated dual-stack UDP/reverse traffic, unaffected native source addresses, controller/agent recovery, withdrawal/drain/address removal, monotonic safe reuse, final release, and immutable diagnostics on three-Node kube-proxy-free Kind; ADRs 0126–0135 |
| 8.6 | Deterministic HA, failover, and multiple addresses | **Verified** | `make egress-ha-kind-test` inherits 8.6a–8.6e and proves authenticated Node-UID-bound promotion, source fencing, exact AFT snapshot/import/readback, exclusive address/reachability handoff, atomic source activation, durable finalization, graceful drain with measured traffic, stable recovery, and abrupt NotReady fail-closed investigation on three-Node dual-stack kube-proxy-free Kind; ADR 0141 |
| 8.6a | Continuity-Certified Rendezvous planner | **Verified** | A bounded provider-neutral compiler pairs IPv4/IPv6 addresses into exclusive ownership shards, assigns exact integer capacity targets, retains the mathematical maximum legal prior ownership, prefers failure-domain-diverse replacement, and precomputes a complete capacity-exact plan for every single-gateway failure. Strict replay verifies membership, plan, contingency, and minimum-disruption certificates under `make egress-ha-planner-test`; ADR 0136 |
| 8.6b | Proof-carrying HA promotion | **Verified** | An epoch- and digest-bound manifest fences every exact source first, then requires exact old-owner address absence or a positive independent infrastructure fence; Kubernetes readiness/Lease is never isolation authority. Exact replacement ownership and atomic reachability compare-and-swap readback create one replay-verifiable activation capability under `make egress-ha-promotion-test`; ADR 0137 |
| 8.6c | Acknowledged Flow Twin continuity | **Verified** | Complete semantic forward/reverse NAT pairs replicate through bounded sequence-checked hash chains. Exact standby snapshot/watermark readback binds Node UIDs, controller/stream epochs, active CCR plan, record count, and local revision. Promotion imports only acknowledged, live, lease- and shard-valid pairs and binds them to one target source bank; loss, replay, reorder, foreign state, expiry, and mutation fail closed under `make egress-ha-continuity-test`; ADR 0138 |
| 8.6d | Durable exclusive ownership and proof alignment | **Verified** | Checkpoint-v3 persists replay-checked CCR plans and freezes membership across health changes. Exact-Node address projections carry only assigned shards plus prior acknowledged state for rollback-safe subset/superset transitions; proof, source, and gateway compilers share CCR selection algorithm v3 and bind the plan digest. Standby certification is withheld until replica readback under `make egress-ha-live-ownership-test`; ADR 0139 |
| 8.6e | Durable promotion transaction | **Verified** | Checkpoint-v4 replays the exact previous plan and every source fence, old-owner/infrastructure fence, staged survivor plan, acquisition, reachability CAS, flow-twin stream/readback, and source-specific bank-bound cutover in order. Health is not evidence and premature staging fails closed under `make egress-ha-transaction-test`; ADR 0140 |
| 8.6f | Authenticated live promotion and measured recovery | **Verified** | Checkpoint-v5 persists terminal source activation and uses a canonical structured-recipient cutover encoding. Agents recover exact source retirement evidence, snapshot and import AFT pairs with BPF readback, revoke old ownership, acquire replacements, and activate the mandated source bank. A verifier-isolated V2 tail-call dispatcher supports Nodes acting as both source and gateway. The repeatable Kind gate observed 45 acknowledged twins, a 10.860-second graceful drain, bounded probe disruption, and an 80.428-second abrupt recovery without treating health as fence authority; ADR 0141 |
| 8.7 | FQDN and internet-access controls | **Verified** | 8.7a–8.7f verify temporal DNS evidence, durable ownership, autonomous packet expiry, resolver-bound wildcard discovery, live multi-Node DNS and classifier lifecycles, and provider-neutral Authority-Carved Internet classification with authenticated durable ingestion and explicit bounded fallback. Operations, scale, provider, and platform gates remain in 8.8–8.11 |
| 8.7a | Provenance-Leased Resolution contract | **Verified** | Schema-v1 view-scoped distinct-observer quorum compiles exact/label-bounded wildcard queries into TTL-capped new-flow and established-drain leases. Complete provenance, deterministic digest/replay, zero-TTL denial, and atomic capacity rejection pass `make egress-fqdn-evidence-test`; ADR 0142 |
| 8.7b | Native intent and durable observation ledger | **Verified** | Native `EgressPolicy` exposes mutually exclusive network/FQDN destinations and bounded resolver-view/quorum/capacity/TTL/grace defaults. Current Pod/Node-bound complete batches distinguish authoritative empty from loss, reject replay mutation/regression, and survive canonical digest-checked ConfigMap recovery. Unresolved intent installs IPv4/IPv6 catch-all ownership and remains fenced even under active admission; `make egress-fqdn-control-test`; ADR 0143 |
| 8.7c | Autonomous PLR observation and enforcement | **Verified** | A bounded Node-local producer resolves admitted exact A/AAAA names with CNAME-minimum TTL, UDP/TCP truncation handling, complete-batch/loss semantics, and authoritative final withdrawal. Controller revision/deadline caching independently verifies PLR snapshots and transactionally refreshes source/gateway banks. Egress ABI v4 plus persistent ABI v15 place conservative monotonic new/established deadlines in the packet path; source tuple memory and gateway NAT state expire without controller availability, while AFT schema v2 re-anchors portable deadlines across Nodes. `make egress-fqdn-dataplane-test`; ADR 0144 |
| 8.7d | Explicit wildcard discovery and live DNS lifecycle | **Verified** | Explicit bounded discovery names and resolver-address allowlists separate suffix policy, name discovery, resolver view, and packet authority. The agent produces independent complete batches per view and final empty withdrawals; PLR replay rejects undeclared wildcard members and foreign resolvers. Equivalent cross-Node replica contracts retain independent provenance but coalesce to one identity-keyed gateway behavior; conflicts fail closed. A three-Node Kind gate requires two observer/source Nodes, two activation grants, custom-view A/AAAA quorum, dual-stack traffic, observer epoch replacement, authoritative-empty denial, recovery, and final withdrawal under `make egress-fqdn-lifecycle-test`; ADR 0145 |
| 8.7e | Authority-Carved Internet classification | **Verified** | A native mutually exclusive internet selector names a classifier, policy exceptions, and default-deny or bounded last-known-good behavior. Schema/algorithm-v1 complete prefix evidence binds provider, epoch/revision, validity, per-rule provenance, and digest. Unknown space denies; most-specific provider decisions apply before absolute policy subtraction; replay rejects mutation/regression. Source and gateway lower identical deadline-bound dual-stack LPM maps and fence deny-closed authority under `make egress-internet-classification-test`; ADR 0146 |
| 8.7f | Authenticated durable classifier lifecycle | **Verified** | A cluster-scoped classifier API, opt-in unbound publisher role, transactional relist, and canonical SHA-256 checkpoint preserve current publications, replay positions, and exact per-intent snapshots. Persistence precedes replacement distribution; loss enters digest-linked bounded LKG even before source validity expires, controller restart preserves it, and packet deadlines deny autonomously. A dedicated three-Node kube-proxy-free dual-stack Kind gate proves publisher/agent RBAC, positive/negative/exception/unknown traffic, loss, restart, expiry, replay/mutation rejection, higher-revision recovery, and cleanup under `make egress-internet-lifecycle-test`; ADR 0147 |
| 8.8 | Reachability and advertisement providers | **In progress** | 8.8a verifies provider-neutral Diversity-Quorum Reachability: exact lease/path plans require finite, independent failure-domain evidence across every declared vantage and fail closed on correlated, conflicting, partial, foreign, or expired views. Durable ingestion, runtime activation, provider implementations, and platform qualification remain |
| 8.8a | Diversity-Quorum Reachability contract | **Verified** | Canonical SHA-256 plans bind owner/provider/revisions/lease/action, exact dual-stack addresses and permitted forwarding identities, ECMP bounds, required vantages, and evidence lifetime. Complete observer views count distinct failure domains rather than replicas; exact within-vantage agreement is mandatory for Ready or Withdrawn, while missing/correlated/conflicting/partial/foreign/expired evidence denies closed under `make egress-reachability-contract-test`; ADR 0148 |
| 8.8b | Authenticated reachability evidence lifecycle | **Planned** | Add publisher/observer APIs and least-privilege identities, durable replay-resistant storage, plan/evidence materialization, expiry scheduling, explanation provenance, and integration with existing reachability acknowledgements and safe release |
| 8.8c | Static/native live reference provider | **Planned** | Replace controller self-acknowledgement with an explicit provider receipt plus independent Node/fabric observers and verify dual-stack activation, conflict, expiry, withdrawal, restart, and exact cleanup in Kind |
| 8.8d | BGP provider and routing policy | **Planned** | Integrate an evaluated routing stack rather than inventing BGP; support bounded dual-stack peers, policy, ECMP, graceful restart, readback, scoped rollback, and DQR observer evidence |
| 8.8e | BFD and failure-correlation integration | **Planned** | Treat BFD as bounded liveness evidence rather than ownership, correlate it with route and dataplane witnesses, and prove deterministic degradation/failover without allowing one control-plane domain to self-quorum |
| 8.9 | Operations, simulation, upgrade, and recovery | **Planned** | Fixed-cardinality metrics/status, NAT and failover history, allocation/gateway/policy explanation, read-only simulation, controller/provider/agent recovery, compatibility, and exact cleanup |
| 8.10 | Kube-proxy-free Kind qualification | **Planned** | Exact committed dual-stack multi-Node lifecycle covering policy, allocation, steering/NAT, HA, recovery, provenance, cleanup, and rollback with immutable evidence |
| 8.11 | OpenShift qualification | **Planned** | Independent digest-pinned cl02 RHCOS/SELinux/CRI-O gate covering cross-worker dual-stack egress, source addresses, failover, recovery, exact cleanup, convergence, and ClusterOperator comparison |

Within 8.5, ADR 0131 verifies the first live safe-forgetting producer. Admitted
membership is captured before invalidation, and current Pod/Node-bound source
agents publish exact fenced-bank evidence under `make
egress-source-retirement-test`. ADR 0132 adds independently authenticated,
lease-specific gateway projection and NAT-LRU drain evidence under `make
egress-gateway-retirement-test`. ADR 0133 adds explicit static reachability,
schema-v2 release projections, exact kernel subset readback, and atomic final
authority consumption under `make egress-release-authority-test`. ADR 0134 adds
proof-bound sparse NAT lifecycle witnesses and exact non-blocking loss evidence
under `make egress-nat-observability-test`. ADR 0135 closes the production join
and a repeatable three-Node dual-stack lifecycle under `make
egress-kind-lifecycle-test`.

## Accepted Phase 8 gate

The phase closes only when one exact committed tuple passes independent Kind and
OpenShift gates and demonstrates:

- explicit ownership: ordinary Pod egress remains native unless admitted egress
  intent selects the source and an owned pool/provider;
- source-side security policy before egress steering, allocation, or NAT;
- identity-aware selection by Namespace, workload, and ServiceAccount without
  treating an IP address as trust identity;
- deterministic conflict-safe dual-stack allocation, multiple-address
  semantics, exact release/reuse, and foreign-state preservation;
- a canonical Egress Behavior Contract independently verified before activation;
- lease-fenced gateway ownership, deterministic HA/failover, split-brain
  rejection, and explicit established-flow behavior;
- IPv4/IPv6 TCP/UDP steering and NAT with exact original source, translated
  source, destination, gateway, policy, allocation, and revision provenance;
- separately revisioned allocation, gateway readiness, reachability, dataplane,
  and publication state with last-known-good recovery;
- FQDN controls with bounded DNS-derived state, TTL/staleness, wildcard,
  capacity, and explanation semantics;
- fixed-cardinality operations, durable history, explanation, and read-only
  simulation that never guesses private NAT state;
- exact route/address/neighbor/map/checkpoint/lease/fixture cleanup; and
- immutable source, image, platform, measurement, and qualification evidence.

## Semantic precedence

For a new egress flow the order is fixed:

1. resolve the source workload identity and direction;
2. enforce source-side security policy against the original destination;
3. match explicit egress intent and destination constraints;
4. fence the identity until an exact admitted contract is active;
5. deterministically select a current owned address and lease-fenced ready
   gateway and derive the bilateral flow proof;
6. create bounded flow/NAT state and steer to that gateway; and
7. publish the translated source only through an acknowledged reachability
   provider.

An existing validated flow follows its documented failover contract. A gateway
or address lease never grants policy permission. FQDN-derived IP membership is a
destination constraint with provenance and expiry, not a workload identity.

## Ownership and compatibility

- The controller adapter owns Kubernetes/OpenShift translation only; normalized
  egress intent contains no provider-specific API strings.
- The egress domain owns pools, leases, gateway candidates, provider intent, and
  canonical contracts. Allocation does not imply reachability or dataplane
  readiness.
- Agents independently verify exact-Node contracts, own host steering/NAT state,
  and activate only coherent revisions. eBPF consumes fixed-width bounded state.
- Gateway and advertisement implementations are provider interfaces. Static
  development reachability, OpenShift compatibility, and future BGP backends do
  not fork policy or NAT semantics.
- Every schema/ABI transition negotiates capabilities, retains last-known-good
  state, stages and reads back inactive state, activates atomically, and cleans
  only exact versioned ownership.

## Default behavior

Safe features are enabled by default only after their milestone is verified.
Unowned traffic remains on native routing; no egress address, gateway, FQDN
rule, BGP advertisement, or cross-cluster route is inferred. Explicit intent
is fenced by default before activation and whenever safe withdrawal begins.
Intent that cannot satisfy its contract fails closed without silently reverting
to native routing or a different source address.

## Explicit exclusions

Phase 8 does not silently claim production BGP/EVPN/ECMP/BFD, cloud-provider
adapters, cross-cluster egress, overlapping-CIDR translation, WireGuard,
application identity from DNS, L7 proxying, Gateway API, SCTP egress NAT,
fragments, generic NAT `RELATED`, arbitrary ICMP error translation, production
HA, availability, or scale. Those require independent architecture and gates.

## Immediate next slice

Milestone 8.8b adds authenticated, durable DQR evidence ingestion. It must bind
publisher identity to observer/failure-domain ownership, reject replay and
same-position mutation, retain exact plans and observations across restart,
schedule finite authority expiry, and bridge only verified assessments into
the existing reachability and Proof of Safe Forgetting transactions. The
static/native live provider follows in 8.8c; BGP and BFD remain independent
8.8d–8.8e gates. Operations, scale, and platform qualification remain in
milestones 8.9–8.11.
