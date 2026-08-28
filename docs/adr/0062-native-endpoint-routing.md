# ADR 0062: Native routing uses exact point-to-point endpoint state

Status: Accepted and implemented through the native kernel lifecycle

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
scope, and output interface. Routes use value 196 as a node-local UNF protocol
convention. It is unassigned in the current
[Linux UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h),
but is not claimed as a global reservation; exact-key preflight remains the
authority and treats a conflicting use as foreign. Standard assignments such as
Open/R 99 and BGP 186 are not reused. Kernel lowering preflights route keys and
exact neighbor tuples before mutation, fails on foreign conflicts, and removes
only exact owned state.

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
shape, namespace direction, output indexes, MAC direction, protocol convention,
zero native overhead, the IPv6 MTU floor, arithmetic bounds, durable/link drift,
typed lowering, and rollback error retention.

Its privileged route gate creates isolated pod, native-host, and remote network
namespaces. It requires IPv4 and IPv6 forwarding through the planned host routes,
container gateway/default routes, and permanent neighbors; exact independent
readback and replay; first and repeated cleanup; and absence of all owned routes
and neighbors afterward. An internal checkpoint injects failure after container
application and requires scoped rollback to leave every route and neighbor absent
while both veth endpoints remain valid. Foreign same-key default-route and
gateway-neighbor fixtures must make apply and delete fail before host mutation,
and both foreign objects must remain unchanged.

All three path links use MTU 1400. IPv4 ICMP payload 1372 and IPv6 payload 1352
pass with fragmentation prohibited; adding one byte fails. Larger 1472-byte IPv4
and 1452-byte IPv6 payloads pass only when source fragmentation is allowed.
Changing either veth endpoint to MTU 1399 makes strict readback fail until the
recorded value is restored. Unit tests separately reject provider/durable MTU
drift, subtraction underflow, and results below the IPv6 minimum.

## Consequences

Milestone 6.5 and sub-items 6.5a through 6.5c are Verified. ADR 0063 now composes
link and route operations with the durable ADD/CHECK/DEL attachment transaction.
Controller block distribution and cross-node node-networking qualification
remain later full-CNI slices.
