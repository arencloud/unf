# ADR 0062: Native routing uses exact point-to-point endpoint state

Status: Accepted; deterministic planning implemented, kernel lifecycle in progress

## Context

ADR 0061 established portable veth ownership but deliberately stopped before
routes. Applying the IPAM node-block prefix directly to every workload endpoint
would make peers in that block appear to share an L2 segment even though each
veth is point to point. Same-node traffic could then ARP or discover neighbors
on the wrong endpoint instead of traversing the host routing and policy path.

The routing architecture must remain replaceable without coupling allocation or
policy to native routing. It also needs an exact ownership shape for later
readback, rollback, and deletion.

## Decision

The new `unf-route` crate defines a `RoutingProvider` boundary. A provider derives
its workload MTU and creates an immutable plan from the durable attachment plus
strict link readback. IPAM continues to retain the node-block prefix as allocation
provenance, while the link applies IPv4 `/32` and IPv6 `/128` workload addresses.

The first `NativeRoutingProvider` declares zero encapsulation overhead. It
rejects an underlay-derived workload MTU outside 1280 through 65535 and rejects
any mismatch between that value, the durable attachment, and kernel link
readback.

For each family, the plan contains:

- a host `/32` or `/128` route to the workload through the host veth;
- a permanent host neighbor from the workload address to the peer MAC;
- a container `/32` or `/128` on-link route to its lease gateway;
- a permanent container neighbor from that gateway to the host MAC; and
- a container default route through that explicit on-link gateway.

All entries carry their namespace role, main-table identity, link or universe
scope, and output interface. Routes use private protocol value 99 as the UNF
ownership marker; standard Linux assignments such as BGP protocol 186 are not
reused. Kernel lowering will preflight route keys and exact neighbor tuples
before mutation, fail on foreign conflicts, and remove only exact owned state.

## Alternatives

Applying the node prefix to the workload interface creates false L2 adjacency.
A default device route without an explicit neighbor can ARP or discover every
remote destination. Assigning the same gateway address to every host veth
creates duplicate local-address and weak-host ambiguity. A permanent gateway
neighbor sends the packet to the host veth MAC without requiring the host to own
the gateway address. Encapsulation, BGP, hybrid, and multi-cluster providers can
implement the same boundary later with declared overhead and separate evidence.

## Verification

`make cni-routing-test` first repeats the real veth gate with routed `/32` and
`/128` addresses, then runs strict unit tests for both-family route and neighbor
shape, namespace direction, output indexes, MAC direction, private protocol,
zero native overhead, the IPv6 MTU floor, arithmetic bounds, and rejection of
durable/link MTU or address drift.

## Consequences

Milestone 6.5 is In progress and planning sub-item 6.5a is Verified. No route or
neighbor is mutated by production code yet. Sub-item 6.5b must implement typed
netlink apply/readback/delete with conflict preservation and rollback, followed
by isolated forwarding and fragmentation qualification in 6.5c. Production CNI
ADD/CHECK/DEL remains fail closed until those operations share the durable
link-plus-route transaction.
