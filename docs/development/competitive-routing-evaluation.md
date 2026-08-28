# Competitive routing evaluation

Last reviewed: **2026-08-28**

This is an engineering input, not a feature-parity or superiority claim. Product
capabilities change, so every comparison must be refreshed from current upstream
or vendor documentation before it affects a release claim. Tigera and Isovalent
are tracked as the enterprise distributions around Calico and Cilium rather than
double-counted as independent datapaths.

## Current documented baseline

| Project/product | Current upstream or vendor baseline | Constraint adopted by UNF |
|---|---|---|
| Calico / Tigera | Calico 3.32 documents native BGP, VXLAN and IP-in-IP, including cross-subnet overlays. Its default iBGP full mesh is described as suitable around 100 Nodes or fewer, with route reflectors recommended at larger scale; IP-in-IP is IPv4-only. [Networking options](https://docs.tigera.io/calico/latest/networking/determine-best-networking), [BGP](https://docs.tigera.io/calico/latest/networking/configuring/bgp), [overlays](https://docs.tigera.io/calico/latest/networking/configuring/vxlan-ipip) | Never couple policy/IPAM to one routing backend; avoid an all-Node peering requirement; require IPv4/IPv6 symmetry from every backend that claims dual-stack support; make topology-aware native/overlay selection possible without changing attachment ownership. |
| Cilium / Isovalent | Cilium 1.20.1 documents VXLAN/Geneve encapsulation and native routing. Automatic direct Node routes require a shared L2 domain; otherwise the underlay or an additional BGP component must distribute routes. [Routing](https://docs.cilium.io/en/stable/network/concepts/routing/) | Native intent must model explicit per-family next hops/interfaces rather than infer one flat L2. Controller intent remains backend-neutral so BGP, overlay and hybrid lowering can replace static native routes without changing CNI or policy state. |
| OVN-Kubernetes | OVN-Kubernetes 1.3 documents per-zone interconnect using OVN-managed Geneve tunnels. Its current RouteAdvertisements API integrates Pod-network/EgressIP advertisements with FRR and supports VRF-oriented designs. [Architecture](https://ovn-kubernetes.io/1.3/design/architecture/), [RouteAdvertisements API](https://ovn-kubernetes.io/1.1/api-reference/routeadvertisements-api-spec/), [uplinks and VRFs](https://ovn-kubernetes.io/master/features/user-defined-networks/uplinks/) | Keep native forwarding independent from an overlay database, but preserve explicit extension points for encapsulation, route advertisement and route domains/VRFs. Recovery and ownership must be provable from local desired state rather than inferred from global database health. |
| Cisco ACI | Cisco's current Kubernetes design guidance treats the data-center fabric and Kubernetes CNI as cooperating layers and covers integration with multiple CNIs. [ACI Kubernetes design](https://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/application-centric-infrastructure/white-paper-c11-743182.pdf) | The open-source native path must remain standard-Linux and fabric-independent. ACI or other fabric integration belongs behind explicit routing/cloud adapters and cannot become a prerequisite for policy, IPAM, observability, or recovery. |

## UNF routing invariants

Every routing provider must preserve these common contracts:

- Provider-neutral, revisioned Node identity and Pod-block intent.
- Exact IPv4/IPv6 ownership, deterministic lowering and bounded validation.
- No shell mutation in production code; kernel state uses typed APIs.
- Complete preflight before mutation, idempotent replay, independent readback,
  scoped rollback, conflict preservation and exact deletion.
- Last-known-good forwarding during controller interruption, followed by explicit
  stale-state retirement when a complete newer snapshot is committed.
- Per-family path choice, MTU derivation and failure visibility; no assumption
  that IPv4 and IPv6 use the same interface or transport topology.
- Backends may be native, overlay, BGP, hybrid or multi-cluster without changing
  endpoint allocation, durable CNI transactions, policy identity, or telemetry
  provenance.

Milestone 6.6b verifies provider-neutral intent and the native static lifecycle;
6.6c verifies complete snapshot distribution, durable last-known-good recovery,
atomic replacement, stale retirement, and acknowledgements for that native
backend. UNF does not yet claim BGP, overlay, VRF, ECMP, multi-cluster, service
advertisement, or comparative superiority. Those capabilities require their own
implementations and repeatable qualification gates.
