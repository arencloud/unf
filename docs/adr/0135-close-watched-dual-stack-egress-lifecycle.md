# ADR 0135: Close the watched dual-stack egress lifecycle

**Status:** Accepted and implemented for Phase 8 milestone 8.5

## Context

ADRs 0113–0134 define and separately verify egress intent, contracts,
allocation, distribution, source steering, gateway NAT, application evidence,
safe forgetting, address release, and sparse lifecycle events. The remaining
gap was the production join: watched Kubernetes state could drive allocation
and gateway intent, but it did not automatically produce the exact source-Node
contracts consumed by agents. End-to-end traffic therefore still depended on
test-injected projections.

The live dual-stack fixture exposed a second gap. Linux answers ARP for an IPv4
host address held on the owned dummy link, but it does not answer Neighbor
Discovery for an IPv6 `/128` through the provider uplink. The gateway could
translate an outbound packet to the correct IPv6 address while the external
peer could not resolve that address for the reverse packet.

Gateway eligibility was also too implicit. A Ready Node participating in the
primary CNI is not necessarily authorized to expose egress addresses. Finally,
startup and release recovery had to retain enough revision authority to issue
an explicit restored withdrawal and to reallocate unchanged watched intent only
after the old lease completed safe forgetting.

## Decision

The controller owns one serialized production reconciliation from watched
state to source distributions. It snapshots the durable allocation/gateway
checkpoint and the identity and policy revisions, selects scheduled non-host
Pods on primary-CNI Nodes, applies canonical Namespace, workload, and
ServiceAccount intent selection, and emits exact source, policy, allocation,
gateway, and reachability facts. Namespace scope is enforced during matching.
An identity shared by Pods on different Nodes is represented once per source
Node, while duplicate identity facts on the same Node remain invalid.

All six contract revision domains must be nonzero and coherent. Applicable
enforced egress policy facts are included; a selected source with no allow path
is not distributed. When no egress NetworkPolicy selects the source, a stable
internal default-allow policy fact records Kubernetes' native default without
turning it into user-owned policy. Materially unchanged input preserves the
distribution revision. Any changed control-plane material clears old source and
gateway contract admission before publishing new exact-Node projections.

A gateway candidate must be Ready and carry both
`network.unf.io/primary-cni=enabled` and
`network.unf.io/egress-gateway=enabled`. The explicit egress label is authority,
not a preference. Restored durable gateway state initializes distribution
revision authority so an empty withdrawal can be issued after restart. Once
safe release is consumed, unchanged watched desired state is reconciled again;
new allocation uses a strictly newer lease epoch.

Gateway address ownership now includes IPv6 publication. The agent binds the
configured native IPv6 uplink name and index into the address plan, enables
proxy NDP on that exact interface, and installs one proxy-neighbour entry for
each owned IPv6 address. Whole-host proxy collision checks, exact readback,
restart replay, subset withdrawal, rollback, and release follow the same
lease-fenced transaction as the `/128` on `unf-egress0`. Proxy removal precedes
address release. The empty Node-UID-owned dummy interface may remain as a safe
resumption marker; no leased address or proxy may remain.

The test flow receiver exposes `/peer` so a qualification can prove that an
unselected workload retains its original native Pod address. The committed
`hack/verify-kind-egress-lifecycle.sh` gate uses an external dual-stack Podman
peer and a dedicated three-Node kube-proxy-free Kind cluster. It exercises:

- watched `EgressPool` and `EgressPolicy` through allocation and exact contract
  activation;
- exact gateway address and proxy-NDP ownership;
- IPv4 and IPv6 UDP steering, translation, reverse traffic, and sparse NAT
  witnesses;
- native source preservation before, during, and after egress retirement;
- controller and all-agent restart recovery;
- source fencing, lease-specific NAT drain, static reachability withdrawal,
  host address/proxy removal, and atomic final release;
- reuse of the same addresses only under a greater lease epoch; and
- a second complete release with machine-readable evidence and retained
  failure diagnostics.

`make egress-kind-lifecycle-test` inherits every focused Phase 8.5 gate before
running that lifecycle.

## Consequences

Milestone 8.5 now has production watched-state input and real dual-stack packet
evidence rather than only independently verified components. IPv6 local-subnet
ownership is functional without conflating the dummy interface, uplink, or
reachability provider. A missing/renamed uplink, disabled/unreadable proxy state,
foreign proxy, partial application, stale Node identity, or incoherent revision
fails before positive application evidence.

The explicit gateway label is an operational prerequisite and prevents every
primary-CNI Node from becoming an accidental egress gateway. Deployments may
select one or more eligible Nodes, but this milestone's platform lifecycle uses
one gateway and makes no HA or failover claim.

This focused Kind proof does not complete Phase 8 milestone 8.10, whose matrix
also requires the later HA, FQDN, provider, operations, rollback, and cleanup
features. It does not qualify OpenShift, BGP/EVPN/ECMP/BFD, cloud reachability,
SCTP NAT, fragments, generic `RELATED`, or arbitrary ICMP translation. Those
remain explicit milestones 8.6–8.11 rather than inferred capabilities.
