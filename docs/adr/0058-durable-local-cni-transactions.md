# ADR 0058: Local CNI attachment transactions are durable and root-authenticated

Status: Accepted and implemented for the full-CNI foundation

## Context

ADR 0057 places durable attachment ownership in the node-local `unf-agent`, not
the short-lived CNI executable. Before IPAM or link work can safely start, the
agent needs a restart-safe transaction model that distinguishes intent from
completed ownership and rejects concurrent or conflicting runtime replays.
This service must not alter existing overlay agents unless an operator explicitly
enables it.

## Decision

`unf-cni-state` defines local transaction schema v1. Every JSON request and
response carries `schemaVersion: 1` and is bounded to 65,536 bytes. One Unix
connection carries one request and one response. Operations are `status`,
`prepare`, `commit`, `begin_abort`, `complete_abort`, `check`, `begin_delete`,
and `complete_delete`. Errors have stable codes for invalid input, incompatible
schema, absence, conflict, invalid transition, persistence failure, and failed
authentication.

The attachment key is `(network, container ID, interface name)`. Prepare records
the exact namespace path and dual-stack-safe MTU and derives a bounded host veth
identity from the complete key. A collision with any retained identity fails
closed. Exact prepare and commit replays are idempotent; a changed specification
conflicts. CHECK requires an exact ready record. Abort and delete each use two
durable steps so a restart cannot mistake cleanup intent for completed cleanup:

```text
absent -> preparing -> ready -> deleting -> absent
                 \-> aborting -> absent
```

The journal is a schema-v1, key-sorted JSON document. Each mutation writes an
owner-only sibling file, synchronizes it, atomically renames it over the journal,
and synchronizes the parent directory. The in-memory map rolls back if persistence
fails. Startup rejects relative or symlinked paths, malformed JSON, incompatible
schemas, unsorted/duplicate keys, non-deterministic host identities, and duplicate
host ownership. `preparing`, `ready`, `aborting`, and `deleting` records all reload
after restart for later reconciliation.

`unf-agent` exposes the service only when `--cni-socket` (or `UNF_CNI_SOCKET`) is
set. The default journal is `/var/lib/unf/cni/v1/attachments.json`. The socket is
owner-only, accepts only kernel-reported UID 0 peers, serializes mutation handling,
times out each connection after five seconds, removes only its owned socket on
clean shutdown, and replaces a stale socket only after proving that it is a Unix
socket with no active listener. Symlinks and non-socket collisions are refused.

This slice records lifecycle intent only. It does not allocate an address, enter
a network namespace, create or delete a link, install a route, attach BPF, or make
`unf-cni` ADD/CHECK return success. Existing overlay deployments do not set the
new option and therefore retain identical startup and dataplane behavior.

## Alternatives

A journal in `unf-cni` would require cross-process locking and would put recovery
policy in every runtime invocation. An unauthenticated or filesystem-permission-
only socket would not bind requests to the kernel's peer identity. One-step abort
or delete records could release future IPAM state before owned host resources are
actually absent. A database adds migration and operational surface without value
for this bounded node-local map.

## Verification

`make cni-transaction-test` exercises the shared state machine, malformed and
incompatible persistence, deterministic ordering, mode-0600 atomic state,
restart reload in every cleanup phase, socket collision and cleanup behavior,
kernel peer-credential enforcement over a live Unix connection, bounded errors,
and strict Clippy. The complete workspace suite contains 191 tests after this
slice. CNI protocol, eBPF, and deployment-render gates remain independently
required before commit.

## Consequences

The local transaction state/API deliverable is Verified. Milestone 6 and CNI
executable/configuration remain In progress because no CNI lifecycle operation
owns resources yet. The next slice can add collision-safe dual-stack node-block
leases to these same prepare/abort/delete durability boundaries before any veth
creation begins.
