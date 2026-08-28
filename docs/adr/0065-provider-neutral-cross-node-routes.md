# ADR 0065: Cross-node routes preserve provider-neutral intent and exact native ownership

Status: Accepted and implemented for remote-route intent and native kernel lifecycle

## Context

ADR 0064 distributes an authoritative dual-stack block to each opted-in agent,
but a local endpoint route does not make another Node's block reachable. Directly
embedding Kubernetes watches, static-route assumptions, or one tunnel protocol
in the CNI transaction would couple endpoint allocation and policy to a single
network topology. It would also make later BGP, overlay, hybrid, VRF and
multi-cluster providers invasive.

Current products support materially different routing models. The dated upstream
baseline in `docs/development/competitive-routing-evaluation.md` therefore informs
extension constraints, but this ADR makes no comparative-superiority claim.

## Decision

`unf-route` defines strict, serializable `RemoteNodeIntent` independently from a
kernel backend. It carries the authoritative remote Node name, UID, assignment
revision and exact IPv4/IPv6 Pod blocks. Native lowering supplies a separate
next hop for each family, including its output-interface index and explicit
on-link behavior. IPv4 and IPv6 may use different interfaces or topology; the
next hop is not assumed to be the remote Node address or to share one L2 domain.

Planning sorts intent deterministically and validates at most 65,536 remote
Nodes in O(n log n) work. It rejects invalid or local-aliasing identity, zero
revisions or interface indexes, duplicate Node names/UIDs, unusable next hops,
next hops inside any local or remote Pod block, and overlap between any local or
remote block. The resulting native plan owns exactly two main-table routes per
remote Node under UNF protocol 196: one IPv4 prefix and one IPv6 prefix, each
with exact destination, prefix, gateway, interface, scope and on-link state.

Kernel apply lists each address family once and preflights the complete desired
destination/table set before mutation. An exact route is replayed; missing routes
are created through typed netlink; any duplicate or non-exact state is foreign
and stops the operation. Creation tracks only state added by that invocation.
Partial apply or strict readback failure rolls back only those additions, so an
exact route that existed before replay is never removed as collateral cleanup.
Readback requires the full set. Reapplying a partially missing set repairs it.
Delete also preflights the full set, removes only exact owned routes, and is
idempotent.

The same scoped-creation tracking now protects the existing endpoint
route/neighbor transaction: a later-stage failure cannot delete exact state that
predated the invocation.

This slice deliberately does not distribute remote intent to agents or run a
long-lived reconciler. It also does not implement BGP, encapsulation, ECMP, VRF,
route aggregation, encryption, service advertisements or multi-cluster routes.
Those remain provider/reconciliation milestones and must reuse the common Node
intent without changing IPAM, CNI attachment ownership, policy or telemetry.

## Alternatives

Installing one route per Pod would increase kernel and control-plane churn while
the authoritative Node block is already aggregatable. Assuming all Nodes share
one L2 would make native routing invalid across routed zones. Using one path for
both families would break asymmetric dual-stack underlays. Treating protocol 196
alone as ownership would risk deleting a same-protocol route with a different
gateway or interface. Blanket rollback of the entire plan would destroy exact
pre-existing state during replay. A generic runtime plugin system is deferred,
as required by the project architecture, until at least two real providers need
it.

## Verification

`make cni-remote-routing-test` repeats the complete local CNI and controller
node-block gates, then runs remote-intent unit/static checks and a privileged
two-namespace native-route gate. Unit coverage proves strict backend-neutral
serialization, input-order independence, per-family path lowering, local/remote
overlap and recursive-next-hop rejection, duplicate identity rejection, and the
65,536-Node bound.

The real gate installs exact IPv4 and IPv6 block routes across separate Linux
network namespaces and proves forwarding, apply replay, strict readback, repair
of a removed IPv6 route, repeatable exact deletion, and preservation of a foreign
same-key route. An invalid IPv6 interface injected after IPv4 creation proves
partial rollback removes the new IPv4 route; repeating that failure with an
exact pre-existing IPv4 route proves scoped rollback preserves it.

## Consequences

Milestone 6.6b is Verified. ADR 0066 subsequently implements and verifies the
controller-to-agent snapshot plus long-lived reconciliation and recovery in
6.6c. No deployed cluster-networking support is claimed until isolated
primary-CNI qualification passes.
