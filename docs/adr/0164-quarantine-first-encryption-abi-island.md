# ADR 0164: Quarantine-First Encryption ABI Island

**Status:** Accepted and implemented for Phase 9.5c

## Context

UNF's qualified policy, Service, and egress dataplane is one 40-map persistent
ABI. Adding encryption maps to that ABI would make every encryption-only layout
change require discarding unrelated last-known-good state. Reusing an
incomplete or unrecognized encryption map set is worse: stale decisions or
Causal Epoch Leases could become packet authority before their provenance is
recovered.

## Decision

UNF gives encryption a separately versioned **encryption ABI island** at
`/sys/fs/bpf/unf/encryption/v1`. It contains exactly:

- `ENCRYPTION_DECISIONS`, a two-bank identity-pair authority map;
- `ENCRYPTION_TRANSPORTS`, a two-bank coalesced transport map;
- `ENCRYPTION_CONFIG`, the one-entry atomic bank selector; and
- `ENCRYPTION_CONNECTIONS`, persistent Causal Epoch Lease flow state.

The existing `/sys/fs/bpf/unf/v15` ABI and its 40 maps do not change. Aya opens
the island with fixed key/value widths and exact capacities matching the shared
eBPF ABI. The agent accepts either zero pins or all four pins. It rejects a
partial inventory, unknown content, symlinked ownership boundary, wrong map
shape, or unreadable state before attaching a new program.

Phase 9.5c implements **Quarantine-First Activation**: the only recoverable
island is an all-zero config with empty decision, transport, and connection
maps. Any active or residual state is refused until the next slice connects
durable Causal Commit Vector readback. This is intentionally stricter than
guessing that old state is safe. The TC object declares and persists the maps
but does not consume them, set a mark, or claim encrypted workload traffic yet.

## Consequences

Encryption map evolution no longer forces healthy policy, Service, egress, or
NAT state to cold-start. Conversely, core ABI changes do not silently reinterpret
encryption authority. Each island has a small exact recovery boundary and can
advance only with its own compatibility proof.

The cost is one additional version lifecycle and cleanup scope. Phase 9.5d and
ADR 0165 subsequently add CCV-backed inactive-bank staging, exact map readback,
atomic configuration publication, and total restart recovery. Exact island
cleanup and downgrade behavior must still be included before Phase 9.5 can
become Verified.

## Verification

`make encryption-map-persistence-test` builds the real BPF object, checks the
four declared and pinned maps, runs focused all-or-none/foreign/symlink tests,
and applies strict Clippy to the agent. Phase 9.5 remains In progress.
