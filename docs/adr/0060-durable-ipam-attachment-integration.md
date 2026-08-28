# ADR 0060: Dual-stack leases share the attachment transaction

Status: Accepted and implemented for full-CNI IPAM

## Context

ADR 0058 introduced a durable attachment state machine without address
ownership. ADR 0059 fixed the modular node-block allocation semantics. Keeping
leases in a second file would make prepare, abort, and delete vulnerable to
cross-file crash windows, while silently changing the schema-v1 attachment shape
would defeat the version boundary it established.

## Decision

The local transaction wire and attachment journal advance to schema v2. Every
new attachment record contains one complete `DualStackLease`. Prepare reconstructs
collision-checked usage from every durable phase, validates it against the exact
provider, allocates both families, and persists the attachment identity, lease,
and `preparing` phase with one atomic journal replacement. An exact prepare replay
returns the retained lease; a changed specification conflicts.

Ready, aborting, and deleting records retain the lease. Complete abort and
complete delete remove the whole record in one durable update, making the pair
available again only after cleanup is declared complete. Exhaustion or a
persistence error restores the prior in-memory map and leaves the last durable
journal intact.

Journal schema v2 stores the exact IPv4 and IPv6 node blocks as provider
provenance. Startup rejects block drift, foreign addresses or gateway/prefix
metadata, duplicate addresses in either family, malformed ordering, and unknown
schema. The agent requires both `--cni-ipv4-block` and `--cni-ipv6-block` whenever
`--cni-socket` is enabled; default overlay startup still enables none of them.

A schema-v1 journal is validated and migrated in key order. Deterministic
lowest-free leases are assigned under the configured blocks and the complete v2
document is atomically persisted before the socket is bound. If validation or
allocation fails, the v1 bytes remain unchanged and the agent refuses startup.
The existing default `/var/lib/unf/cni/v1/attachments.json` path is deliberately
retained so an upgrade discovers and migrates prior state; the document's own
schema field, not the historical directory name, is authoritative.
Schema-v1 transaction requests are rejected; there was no released CNI client
using that API, and the `unf-cni` executable remains deliberately disconnected
until it can apply and validate links.

Controller delivery of node-block intent remains a later cluster-networking
slice. Explicit startup blocks are sufficient only for isolated fixture work and
are not a production configuration claim.

## Alternatives

Two journals cannot atomically express attachment plus lease ownership. Reusing
schema v1 would cause an older reader with strict unknown-field rejection to fail
without a declared compatibility boundary. Releasing at begin-delete could
reallocate an address while the old host link still exists. Discarding all v1
records is unnecessary because the prior implementation could not create links
or IPAM state and can be migrated deterministically.

## Verification

`make cni-ipam-test` covers provider semantics, allocation and exact replay,
restart retention in every phase, release/reuse only after completed cleanup,
family-specific exhaustion without partial mutation, successful deterministic v1
migration, failed migration without source mutation, exact block provenance,
duplicate durable lease rejection, machine-readable exhaustion, opt-in CLI
requirements, and strict lint. The complete workspace suite contains 202 tests.

## Consequences

Milestone 6.3 IPAM is Verified. No link, address, route, neighbor entry, BPF
attachment, controller block assignment, or CNI result is created yet. Milestone
6.4 portable veth lifecycle is next; existing overlay deployment remains
unchanged and OpenShift is not required for its initial namespace/link unit and
isolated Kind work.
