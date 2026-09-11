# ADR 0223: Content-Verified Compact Frontier

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The recovered five-Node cl02 rollout crossed image startup without publishing
packet authority, then stopped at its durable generation barrier. The exact
frontier and fleet-local plan required 1,955,398 JSON bytes, exceeding the
controller's deliberate 900,000-byte ConfigMap data bound. The smaller Kind
topology had not exercised this cardinality. Splitting the frontier and plan
into independent writes would fit but would make restart recovery tearable.

The same recovery also exposed a release-engineering error: OCI configuration
IDs had been recorded as though they were registry manifest digests. Quay
correctly rejected those references as unknown before a container ran.

## Decision

UNF introduces the **Content-Verified Compact Frontier**. The producer
checkpoint and its exact optional fleet plan are serialized into one strict
schema-v1 envelope, compressed with deterministic gzip, and stored in one
ConfigMap `binaryData` value. A separately encoded descriptor binds the codec,
compressed and decoded lengths, and SHA-256 digests of both representations.

Restore requires the descriptor and payload together, verifies the compressed
digest before decoding, caps decoded output at 64 MB, verifies decoded length
and digest, rejects unknown fields/codecs, then independently replays the
existing frontier and plan cryptographic invariants. The existing 900,000-byte
stored bound remains. Legacy `frontier.json`/`plans.json` checkpoints are read
for adjacent compatibility and migrate on the next atomic write.

Before any Phase 9 OpenShift mutation, the deployer now asks the registry for
each exact controller, agent, and test-tools reference and requires the named
digest to resolve to a Linux/amd64 manifest. A configuration ID can no longer
pass this boundary merely because it has digest syntax.

## Consequences

- Repetitive high-cardinality plan structure no longer consumes one byte per
  repeated JSON field in etcd, while frontier and plan remain one atomic object.
- Compression is storage-only. It adds no packet-path work and grants no
  encryption, policy, key, route, or activation authority.
- Corruption, truncation, decompression expansion, unsupported formats, and
  post-decode semantic mutation fail closed before restored state is published.
- The implementation is explicitly bounded rather than claiming unlimited
  cluster scale; larger scale still requires measured evidence.

## Verification

The controller test constructs a 128-member canonical fleet-plan cut, requires
greater than two-to-one reduction beneath the stored bound, round-trips the
exact producer/plan, and rejects payload and descriptor corruption. The
existing frontier recovery gate checks this regression, strict Clippy covers
the implementation, and the OpenShift gate checks registry-manifest preflight.
Fresh complete Kind qualification and the independent cl02 gate remain
mandatory before Phase 9 closes.
