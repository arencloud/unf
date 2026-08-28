# ADR 0059: Node-block IPAM is modular, dual-stack, and bounded

Status: Accepted; durable integration completed by ADR 0060

## Context

The master prompt requires modular IPAM and explicitly prevents IPAM from
dictating the routing architecture. ADR 0057 assigns pool/node-block intent to
the controller and durable leases to the local agent. ADR 0058 supplies the
attachment transaction boundary, but allocation semantics must be fixed and
tested before its journal schema can safely add leases.

The first full-CNI fixture is dual stack. Allocation must therefore succeed or
fail for both families together, reconstruct collision-free usage after restart,
remain deterministic under retries, and avoid work proportional to a potentially
vast IPv6 block.

## Decision

`unf-ipam` owns address/block/lease types and an `IpamProvider` trait. It imports
neither Kubernetes nor routing or CNI transaction state. The first
`NodeBlockProvider` receives one controller-assigned canonical IPv4 block and one
canonical IPv6 block. Blocks must have at least one workload address: IPv4
accepts `/0` through `/30`, and IPv6 accepts `/0` through `/126`.

For IPv4, the network address, first host gateway, and broadcast address are not
allocatable. For IPv6, the subnet-router anycast/network address and first host
gateway are not allocatable. Allocation chooses the lowest unused workload
address independently in each block and returns both as one `DualStackLease`.
The provider does not mutate the usage snapshot, so exhaustion in either family
cannot partially consume the other family.

Allocation and retained usage are capped at 65,536 leases per node even when a
block contains more addresses. This bounds `/0` and typical IPv6 `/64` searches.
`UsedAddresses` reconstructs usage from durable leases, rejects a duplicate in
either family without partial insertion, and releases only when both addresses
are present. Provider validation requires the exact prefix, gateway, and
workload range for both families, preventing a retained lease from silently
moving between node-block configurations.

The allocation core owns no persistence. The next IPAM slice will extend the
attachment journal under a versioned migration, allocate during prepare, retain
through ready/deleting/aborting recovery, and release only on complete abort or
complete delete. Controller distribution and configuration provenance remain
separate later work; hard-coded cluster blocks are not accepted as a support
claim.

## Alternatives

Enumerating every address in a block would be unsafe for IPv6. Random selection
would require durable randomness and complicate retry/recovery evidence.
Embedding routes in a lease would couple allocation to the native routing
provider prematurely. Letting IPv4 succeed before IPv6 would leave half-created
dual-stack attachments. Delegating to host-local immediately would not exercise
the controller-assigned node-block ownership selected by ADR 0057.

## Verification

`make cni-ipam-test` exercises canonical and malformed blocks, reserved
boundaries, deterministic allocation, independent IPv4 and IPv6 exhaustion,
collision-checked reconstruction, atomic release/reuse, foreign lease rejection,
large-block bounds, strict stable serialization, and provider-trait use. The
complete workspace suite contains 199 tests after this slice.

## Consequences

At this allocation-core checkpoint, milestone 6.3 remained In progress and no
address was written to the attachment journal. ADR 0060 subsequently verifies
durable lease integration and closes 6.3; ADRs 0061–0063 subsequently verify
link, route, and atomic CNI integration. Controller node-block distribution and
cluster primary-CNI installation remain. Existing overlay deployments are unchanged.
