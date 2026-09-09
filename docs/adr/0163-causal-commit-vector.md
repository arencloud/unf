# ADR 0163: Causal Commit Vector for encryption activation

**Status:** Accepted and implemented for Phase 9.5b

## Context

The 9.5a compiler produces a complete inactive encryption generation, but four
independently meaningful facts can still race at activation: policy authority,
Service/backend selection, egress-gateway selection, and the kernel WireGuard
epoch. Treating the BPF configuration pointer as sufficient evidence would
make a crash between staging and publication ambiguous. Treating individual map
entries as self-authorizing could expose a mixed generation.

## Decision

UNF introduces a **Causal Commit Vector (CCV)** and a durable fast-path map
transaction.

The CCV binds the generation and target bank, policy/Service/egress revisions,
decision and transport counts, fast-path state digest, exact active and optional
draining epochs, and every distinct committed kernel-configuration digest. A
canonical digest seals the complete vector. Epoch lifecycle must be consistent
across all coalesced transports, with exactly one active epoch and at most one
draining epoch.

The transaction follows a persist-before-mutate protocol:

1. persist `Prepared` intent while the current active bank is untouched;
2. replace the inactive bank and independently replay its complete state;
3. persist `Staged` with the exact readback digest;
4. flip the single configuration pointer;
5. read back both the published generation and target bank; and
6. persist `Committed`.

Recovery is total for every checkpoint/observation combination. It selects only
clear-and-restage, activate an exact staged bank, commit an exact observed
publication, reuse an exact committed generation, confirm rollback, or refuse
unknown state. Rollback requires the exact prior generation to remain active
and positive absence of the target bank. A partial, mutated, unexpectedly
published, or digest-mismatched bank is never inferred safe.

The transaction and CCV contain only public commitments. They are strict
serializable checkpoints with no private-key material. Platform-specific Aya
map writes and durable file storage consume this contract in the next 9.5
slice; therefore milestone 9.5 remains In progress and this ADR makes no live
packet or persistence claim by itself.

## Consequences

One constant-size record explains whether a generation is causally coherent
across policy, traffic selection, transport, and rotation. Restart behavior is
deterministic even around the publication instruction, while the last-known-
good active bank is never overwritten during staging. The cost is one explicit
readback barrier and one durable transition before and after publication.

## Verification

`make encryption-fast-path-transaction-test` verifies canonical CCV issuance,
kernel-commitment deduplication, strict replay, every pointer-flip recovery
state, mutation and unknown-field refusal, no private material, and rollback
requiring exact prior authority plus positive target-bank absence.
