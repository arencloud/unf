# ADR 0232: Crash-Residue Cleanup Closure

- Status: Accepted and implemented for Phase 9.9 recovery
- Date: 2026-09-11

## Context

The first fresh Kind qualification of Expired Authority Recovery completed the
encryption lifecycle and Phase 8 egress coexistence, then correctly failed its
final no-CNI rollback. One Node retained
`.service-snapshot.json.pending.tmp`. Agent shutdown had interrupted the
owner-only atomic-write sequence after file creation and before rename. The
rollback recognized the durable and pending service checkpoints but did not
recognize the pending checkpoint's atomic temporary file.

Deleting arbitrary state-directory content would hide corruption or foreign
ownership. Refusing every temporary, however, makes an otherwise exact rollback
non-recoverable at a normal process interruption boundary.

## Decision

Add **Crash-Residue Cleanup Closure** to the isolated Kind rollback. After all
agents have stopped, it recognizes the finite set of temporary names produced
by UNF's atomic durable writers. Each candidate must be a non-symlink regular
file, owner-only mode `0600`, and no larger than the product's 64 MiB durable
state bound before deletion. The same rules cover the Node-local key
authority's `.authority.json.tmp`; its contents are never read or exported.

Unknown names, wrong types, symlinks, permissive modes, and oversized files
remain hard failures. Both the complete rollback and idempotent interrupted
rollback path invoke the cleanup, so a retry can finish from the exact partial
boundary observed by the gate.

## Consequences

- A termination between durable temporary sync and atomic rename no longer
  strands an otherwise valid no-CNI rollback.
- Cleanup authority is closed over known producer filenames rather than a glob
  or recursive deletion.
- Private key crash residue is removed by metadata-validated exact name without
  exposing its bytes.
- Runtime packet behavior and persistent BPF ABI are unchanged.

## Verification

`make primary-cni-installer-test` checks shell syntax and the exact service,
LoadBalancer, and private-key temporary ownership vocabulary. The accepting
test is a fresh `make encryption-phase9-kind-test` run through successful
no-CNI rollback, followed by the digest-pinned five-Node cl02 qualification.
