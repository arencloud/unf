# ADR 0284: Mixed-Phase Reciprocal Key Recovery

Date: 2026-09-13

Status: implemented; platform qualification pending, cl02 first

## Evidence and boundary

ADR 0283's full cl02 migration failed after its successful missing-frontier
recovery. Public metadata subsequently showed four Nodes Active on epoch 389
and one still Prepared. The restarted controller required every member to be
Prepared before opening a reciprocal witness round. It therefore could not
reconstruct this unfinished activation. Split generation journals and an
unknown predecessor epoch remain separate recovery findings; this change alone
does not claim complete attribution or repair of the migration failure.

## Decision

Intersect the at-most-two retained public epochs across the exact authenticated
membership. A round requires one common, currently valid, non-Draining epoch
with at least one Prepared or MutuallyAttested member. Active peers may witness
the unfinished activation without changing their keys. Fully Active cuts do
not reopen rounds. Current rounds retain their immutable issuance and rows;
controller replacement reconstructs a fresh round and requires every current
Node's authenticated witness again. No partial quorum, expiry extension,
identity substitution, custom cryptography or new packet authority is added.

Before witnessing or binding a complete cut, the agent verifies its retained
public epoch against the proposal's exact identity, topology, barrier and
lifetime; every round proposal must still be live. Draining, revoked, missing
and replaced authority cannot witness. WireGuard path proof remains a separate
required dataplane boundary.

Complete columns now persist in one atomic authority transaction rather than
one transaction per peer. Existing durable partial acknowledgements are never
overwritten: their peer/target/epoch/barrier/public-epoch bindings must exactly
match, and their observation time cannot exceed the reconstructed round's.
Only missing acknowledgements are added. Ordinary single-ack mutation rejection
is unchanged. Persistence failure leaves the in-memory authority unchanged;
already-attested or active replay performs no persistence write. Peer lookup
uses an ordered index rather than repeated linear scans. Complete-column
insertion validates the exact required-peer set, constructs readiness once and
advances the authority revision once, avoiding repeated whole-authority
validation and hashing inside the per-peer loop.

This reduces persistence transactions deterministically; it is not a measured
CPU, latency, throughput or heavy-load claim. Schemas and key lifetimes are
unchanged. No private key material appears in controller state or test evidence.

## Verification

Focused regressions cover mixed Prepared/MutuallyAttested/Active restart,
all-member quorum, no fully-Active reopening, partial-ack replay, conflicting
bindings, one-write completion, persistence failure, identity/barrier/lifetime
changes, expiration, revocation, draining exclusion and normal next-epoch
rotation. Controller ingestion exercises partial consumption across replacement;
the existing agent durable complete-cut test exercises the new atomic path.

Local verification passed 732 workspace tests with 25 specialized tests
explicitly excluded, strict all-target/all-feature workspace Clippy, formatting
and both platform static gates. These are not live platform results.
Publish immutable images, then verify preserved-state cl02
recovery and the full lifecycle gate before matching-image Kind qualification.
Phase 9 and stabilization/scale readiness remain open.
