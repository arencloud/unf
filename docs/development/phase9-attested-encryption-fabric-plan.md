# Phase 9 attested encryption-fabric execution plan

Last reviewed: **2026-09-10**

Phase 9 implements master-prompt §25 as an identity-bound encryption fabric.
It starts with kernel WireGuard for intra-cluster L3 transport and prepares a
clean contract boundary for the later multi-cluster phase without claiming
cross-cluster behavior. Policy authorization, encryption requirements, key
authority, kernel configuration, path evidence, and publication remain
separately revisioned. The authoritative state remains in
[project-status.md](../project-status.md).

## Milestone summary

| ID | Milestone | State | Exit evidence |
|---|---|---|---|
| 9.1 | Architecture and acceptance boundary | **Verified** | ADR 0158 fixes policy-before-encryption precedence, the Attested Encryption Path Contract, Node-local private-key ownership, Flow-Stable Epoch Rotation, the Intent-Coalesced Cryptographic Fast Path, fail-closed required mode, transactional recovery, performance evidence, independent Kind/OpenShift gates, and explicit exclusions; `make encryption-fabric-boundary-test` prevents drift |
| 9.2 | Encryption intent and path-contract model | **Verified** | `unf-encryption` provides a bounded canonical cluster baseline plus monotonic identity-pair intent and schema-v1 exact-source-Node Attested Encryption Path Contracts. Policy precedes public-key/epoch and bidirectional route admission; Node identities, lifetimes, capabilities, Pod CIDR `AllowedIPs`, interface/route/fwmark/MTU facts, and five revisions bind domain-separated golden digests and witnesses. Independent replay, explicit deny-only failure envelopes, mutation/property/strict-wire tests, and Clippy pass `make encryption-contract-test`; ADR 0159. No private key or runtime mutation exists |
| 9.3 | Node key authority and epoch rotation | **Verified** | `unf-encryption` generates X25519/WireGuard keys directly from the OS CSPRNG into zeroizing memory, exposes secret material only to the future local kernel-provider boundary, and copy-persist-commits at most two epochs to a digest-checked atomic mode-0600 Node-UID-bound checkpoint. The Causal Epoch Barrier seals the exact affected-peer frontier/topology revision and requires every authenticated acknowledgement before activation; rotation, positive zero-flow/zero-route retirement, emergency revocation, public-only monotonic publication, replay/replacement fencing, restart/tamper recovery, and strict Clippy pass `make encryption-key-authority-test`; ADR 0160. No interface or packet mutation exists |
| 9.4 | Transactional kernel WireGuard provider | **Verified** | Typed Rust generic-netlink/rtnetlink configures bounded dual-stack interfaces, complete peer sets, isolated routes, fwmarks, and derived safe MTUs. Proof-Carrying Kernel Transactions bind secret-free before/desired/readback digests and total restart actions; exact ownership aliases, sorted overlap/route indexes, injected rollback, foreign-state preservation, readback/replay, adjacent capability negotiation, and positive cleanup pass `make encryption-kernel-provider-test` plus the independently privileged `make encryption-kernel-provider-live-test`; ADR 0161. No workload packet selects the staged table |
| 9.5 | Intent-Coalesced Cryptographic Fast Path | **In progress** | Phase 9.5a adds the canonical compiler and Causal Epoch Lease. Phase 9.5b adds the Causal Commit Vector and total recovery contract. Phase 9.5c–9.5f add the isolated proof-carrying Aya ABI, Cooperative Route-Mark Lease, and Route-Before-Authority. Phase 9.5g–9.5h add authenticated exact-successor delivery and the non-serializable Tri-Plane Causal Activation Latch. Phase 9.5i–9.5k add the durable complete frontier and authenticated fact reconciliation; 9.5l makes local proof ordering a consuming capability ladder. Phase 9.5m–9.5o add real Linux convergence, fact-first exact-echo exchange, immediate admitted-capability consumption, and fresh proof reconstruction before restart quarantine/TC attachment. Phase 9.5p–9.5u add snapshot-first compilation, sealed runtime delivery, atomic fleet plans, and key transparency. Phase 9.5v derives stable cluster/Node bootstrap, creates or restores durable local keys, and publishes only public state. Phase 9.5w freezes that state into an authenticated reciprocal witness matrix and durably advances Nodes only after complete-fleet release. Phase 9.5x produces an atomic demand-sparse fleet plan with explicit authority-free dormant members under `make encryption-fleet-plan-producer-test`; ADRs 0168–0185. Kubernetes fact projection, controller and local compiler invocation, TC consumption/verifier, and encrypted traffic remain before Verified |
| 9.6 | Bidirectional live path proof | **Planned** | Authenticated nonce-bound readback from both endpoint Nodes proves exact peer/key epoch, route/interface/MTU, kernel counters, and encrypted challenge delivery before activation. Expiry, disagreement, endpoint roaming, one-sided readiness, replay, and underlay mutation deny closed without treating a handshake timestamp alone as path proof |
| 9.7 | Operations, upgrade, recovery, and performance | **Planned** | Fixed-cardinality status/metrics, loss-explicit history, explanation and non-authoritative simulation expose requirement, contract, epoch, peer, path, rotation, and denial provenance without secrets. Adjacent upgrade/rollback, controller/agent outage, Node replacement, exact cleanup, and committed plaintext/encrypted throughput/latency/CPU/memory/rotation measurements pass |
| 9.8 | Kube-proxy-free Kind qualification | **Planned** | One exact committed runtime passes a multi-Node dual-stack gate for required/default and selective encryption, externally verified ciphertext-only underlay transport, Service and egress composition, rotation, failure/recovery, observability, performance capture, exact cleanup, and no-CNI rollback |
| 9.9 | OpenShift qualification | **Planned** | The exact Kind-qualified images independently pass a five-Node dual-stack cl02 RHCOS/SELinux/CRI-O gate with immutable provenance, cross-worker encrypted traffic, rotation/recovery, exact cleanup, convergence, kube-proxy absence, and ClusterOperator comparison |

## Accepted Phase 9 gate

The phase closes only when one exact committed tuple passes independent Kind
and OpenShift gates and demonstrates:

- source identity and security policy authorize the original flow before any
  encryption decision, route, tunnel, Service translation, or egress steering
  can broaden connectivity;
- newly installed Phase 9 UNF primary-CNI clusters require encryption for every
  managed cross-Node Pod path by default after qualification; same-Node traffic
  records that no underlay hop exists, while explicit selective intent may add
  requirements but never weaken a required cluster baseline;
- an upgraded cluster retains its last-known-good transport until a staged,
  explicitly acknowledged activation proves every required path, preventing
  both surprise outages and silent plaintext downgrade;
- the Attested Encryption Path Contract binds source/destination identities and
  Node UIDs, cluster identity, original traffic domain, policy and routing
  revisions, WireGuard public-key digests and epochs, interface/route/MTU facts,
  lifetime, and capabilities before either endpoint activates it;
- private keys originate and remain on their owning Node; the controller
  distributes authenticated public state and orchestration only, and no UNF
  API, Kubernetes object, diagnostic, event, metric, or durable controller
  checkpoint contains private-key material;
- WireGuard's kernel implementation owns cryptographic primitives. UNF does not
  implement ciphers, key agreement, packet encryption, or configurable cipher
  suites; provider evolution is versioned instead of inventing crypto agility;
- exact AllowedIPs and policy-routing ownership is disjoint and replayable so a
  prefix cannot ambiguously select two peers in one active epoch;
- identity-level requirements coalesce onto bounded Node/epoch transports, with
  no interface or peer per workload/policy and no userspace packet forwarding;
- required new flows fail closed whenever their contract, peer epoch, route,
  MTU, bidirectional evidence, or kernel readback is absent, stale, conflicting,
  or withdrawn; they never fall back to plaintext;
- two-epoch rotation moves only new flows after both sides are ready, retains
  bounded established-flow continuity on the prior epoch, then retires the old
  interface/key only after positive drain and exact route absence evidence;
- encrypted transport composes with ClusterIP, NodePort, LoadBalancer, DSR, and
  egress-gateway selection without changing their policy or ownership semantics;
- status, explanation, simulation, history, and diagnostics state exactly what
  is authoritative, observed, derived, expired, unavailable, or loss-affected;
- throughput, latency distribution, CPU, memory, map operations, peer scale,
  handshake convergence, MTU cost, and rotation disruption are compared with a
  committed plaintext baseline before a performance claim is accepted; and
- schema, route, interface, key-metadata, map, checkpoint, fixture, and CNI
  cleanup is exact, version-scoped, restart-safe, and refuses foreign state.

## Semantic precedence

For a new managed flow, the order is fixed:

1. resolve the authenticated source identity and original destination;
2. apply source-side security policy to the original tuple;
3. apply Service/backend or egress-gateway selection without losing original
   identity and policy provenance;
4. resolve the cluster baseline plus any identity/destination encryption intent;
5. independently validate the exact Attested Encryption Path Contract;
6. select one active Node/epoch transport and write compact flow provenance;
7. route into the kernel WireGuard device; and
8. verify remote delivery against the same contract and epoch.

An established flow may remain on its admitted prior epoch only within the
bounded rotation drain window. Policy denial always wins. Encryption state does
not grant policy permission, Service eligibility, egress ownership, or route
reachability.

## Attested Encryption Path Contract

The contract is a canonical authorization envelope, not a key and not proof of
packet delivery by itself. It binds:

- source/destination cluster, identity, Node name, and Node UID;
- original destination class plus the selected transport endpoint;
- policy, identity, route, Service/egress, encryption-intent, and key revisions;
- provider/schema/capability versions and the public-key digest for each Node;
- active epoch, endpoint, disjoint AllowedIPs, interface identity, route table,
  fwmark, MTU, lifetime, and permitted failure outcomes; and
- a domain-separated digest and compact decision witness.

Each agent independently reconstructs the contract from authenticated inputs,
reads back only its owned kernel state, and publishes nonce-bound evidence. The
controller may join matching evidence but cannot manufacture endpoint proof.
Activation requires agreement from both endpoint Node identities plus a live
encrypted challenge bound to the contract digest. A recent WireGuard handshake
alone is liveness evidence, not proof that the selected workload path used the
tunnel.

## Intent-Coalesced Cryptographic Fast Path

Encryption authority remains per identity and destination, but transport is
coalesced by exact `(trust domain, destination Node UID, key epoch, path class)`.
The compiler emits a bounded fixed-width decision that selects one of at most
two admitted epoch banks. Many contracts can therefore share one Node peer and
kernel tunnel without duplicating interfaces, peers, routes, or encryption
work. The packet path performs bounded map lookups and marking only; key
agreement and authenticated encryption stay in kernel WireGuard.

Coalescing is legal only when the complete transport tuple is identical. It
cannot merge distinct trust domains, key epochs, destination Nodes, MTUs,
required/disabled semantics, or route ownership. Capacity failure is detected
before staging and retains the last-known-good bank.

## Key and rotation ownership

- Each agent generates its private key from the OS CSPRNG through a maintained
  WireGuard library/interface, zeroizes temporary userspace buffers where the
  dependency permits, programs the kernel through the provider, and stores only
  the minimum mode-0600 Node-local material needed for restart. The private key
  is never sent to the controller.
- Authenticated Node UID owns one public key per provider epoch. Recreated Nodes
  cannot inherit an old key merely by reusing a name or address.
- Rotation uses `Prepared -> MutuallyAttested -> Active -> Draining -> Retired`.
  Only two epochs may coexist, and every transition is monotonic and durable.
- New flows switch atomically only after all required remote peers attest the
  prepared epoch. Existing admitted flows drain on the old epoch until their
  bounded deadline; expiry or revocation fails them closed.
- Emergency revocation fences affected required traffic before withdrawing
  owned routes and key metadata. Availability never overrides revocation.

## Default behavior

Milestone 9.1 changes no runtime behavior. After the complete phase qualifies,
fresh UNF primary-CNI installations default managed cross-Node Pod transport to
`Required`. Existing installations use an explicit staged migration that first
proves complete encrypted reachability; until activation, their previously
qualified native behavior remains unchanged. Once a flow or cluster baseline is
Required, missing encryption denies rather than downgrades. Host-network,
external Internet, and control-plane traffic are not claimed unless selected by
a later explicit contract.

## Measurement rule

No algorithm or performance advantage is accepted without a reproducible
fixture. The same topology and traffic distributions must compare native and
encrypted paths across IPv4/IPv6, packet sizes including the derived MTU edge,
peer counts, concurrency, Service modes, egress-gateway composition, and
rotation. Evidence records throughput, p50/p95/p99 latency, CPU time, memory,
map writes/lookups, handshake and convergence time, drops, retransmits, and
rotation interruption. Results publish regressions as well as improvements and
select a bounded fallback only when it does not violate Required semantics.

## Explicit exclusions

Phase 9 does not silently claim cross-cluster transport, overlapping-CIDR
translation, global services, mTLS or application identity, post-quantum
cryptography, custom cryptographic primitives, hardware/TPM attestation,
IPsec/MACsec, L7 proxying, Gateway API termination, transparent host-network or
control-plane encryption, production availability, or production scale. Those
require independent architecture and gates.

## Immediate next slice

Complete milestone 9.5 by projecting Kubernetes facts into the 9.5x
authoritative catalog producer and feeding its output to the Node-local compiler and exact
exchange/activation/restart path;
invoke bounded lookup after policy plus Service/egress selection in TC; and pass
verifier, restart, rotation, revocation, IPv4/IPv6, Service, egress, and
live-kernel traffic gates. The compiler/ABI, transaction contract, isolated
persistence foundation, and proof-carrying map
mirror, cooperative mark, policy-route activation, authenticated causal
delivery, tri-plane activation, cluster-complete publication, controller restart
recovery, authenticated complete-cut fact reconciliation, capability-typed
local proof ordering, concrete Linux convergence, Echo-Sealed exchange,
proof-rehydrating restart activation, snapshot-first local plan compilation,
the causally sealed input manifold, nonce-bound plan relay, persist-before-
compile runtime inbox, fleet-synchronous catalog, public-key transparency cut,
durable edge-key bootstrap, reciprocal key witness matrix, and demand-sparse fleet plan forge now pass their focused gates, but no workload
packet-path activation is claimed yet.
Live two-ended encrypted challenge proof remains milestone 9.6.
