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
| 8.7 | FQDN and internet-access controls | **In progress** | 8.7a verifies the provider-neutral temporal evidence contract. Native API/defaults, authenticated observation and durable refresh, transactional source/gateway lowering, live dual-stack enforcement, internet classification/fallback, explanation/simulation/recovery, and platform qualification remain |
| 8.7a | Provenance-Leased Resolution contract | **Verified** | Schema-v1 view-scoped distinct-observer quorum compiles exact/label-bounded wildcard queries into TTL-capped new-flow and established-drain leases. Complete provenance, deterministic digest/replay, zero-TTL denial, and atomic capacity rejection pass `make egress-fqdn-evidence-test`; ADR 0142 |
| 8.8 | Reachability and advertisement providers | **Planned** | Static/native development provider first; BGP advertisement remains a replaceable provider with independent route-policy, ECMP, graceful-restart, BFD, and production qualification gates |
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

Milestone 8.7b adds native API/defaulting plus authenticated, durable DNS
observation and refresh state around the verified PLR contract. It must preserve
resolver-view isolation and monotonic source epochs across restart, distinguish
an empty valid answer from observation loss, withdraw expired authority without
partial updates, and keep explicit network/internet fallback separate. Later
8.7 slices lower verified leases transactionally, prove live dual-stack
enforcement, and integrate explanation, simulation, recovery, and platform
qualification without weakening the verified 8.6 HA path.
