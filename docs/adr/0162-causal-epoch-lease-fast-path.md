# ADR 0162: Causal Epoch Lease fast path

**Status:** Accepted and implemented for Phase 9.5a

## Context

Encryption intent is identity-specific, while kernel WireGuard is naturally a
Node-to-Node transport. Materializing an interface, peer, or cryptographic
operation per identity pair would impose unbounded control-plane and kernel
cost. Conversely, selecting a tunnel only by destination Node would erase the
policy, Service/backend, egress-gateway, contract, and epoch authority that made
the flow legal.

Rotation adds a second conflict: new flows must switch atomically, but an
established flow must not jump epochs mid-connection. A stale flow entry also
must not survive policy denial, revocation, or a finite drain deadline.

## Decision

UNF introduces the Intent-Coalesced Cryptographic Fast Path and its **Causal
Epoch Lease (CEL)**.

- The compiler emits one explicit decision per source/destination identity
  pair, including Native decisions. Absence is never interpreted as Native
  after the feature is active.
- Required decisions bind policy, Service, and egress revisions, the exact
  Attested Encryption Path Contract revision and witness, and its key epoch.
- Transports coalesce only when trust domain, local and destination Node UIDs,
  key epoch, path class, interface/index, route table, fwmark, MTU, committed
  kernel-configuration digest, readiness digest, and contract revision match.
  Lifecycle state is deliberately excluded from transport identity so
  `Active -> Draining` preserves existing leases.
- A domain-separated, content-derived 64-bit transport ID is collision checked
  before staging. Bounded compilation accepts at most two epochs, 65,536
  decisions, and 4,096 transports.
- A complete inactive logical bank is lowered to fixed-width ABI records. One
  configuration record is the atomic publication point for new flows.
- A new Required flow can select only the active epoch. Its CEL records the
  identity-keyed flow ownership, transport ID, contract revision, epoch,
  witness, and last-seen time. An established CEL can select a draining epoch
  only through the bounded deadline.
- Policy denial always precedes CEL reuse. Missing, stale, mismatched,
  noncommitted, expired, or revoked authority drops Required traffic and never
  falls back to plaintext.
- Kernel WireGuard remains the only cryptographic implementation. The packet
  decision performs map lookup, validation, bounded lease handling, and mark
  selection; it implements no cryptographic primitive.

The Phase 9.5a slice implements the canonical compiler, fixed-width shared ABI,
verifier-friendly transport predicate, and executable packet-decision mirror.
The next 9.5 slice must install/persist the maps, connect the decision after the
existing policy and Service/egress stages in TC, program exact policy routing,
and pass verifier plus live-kernel traffic gates. Until that lands, milestone
9.5 remains In progress and no workload packet is claimed to use WireGuard.

## Consequences

Many identity contracts can share one kernel transport without sharing
authorization. Rotation changes constant-size configuration authority rather
than rewriting every established flow, while CELs preserve continuity without
granting policy permission. Binding selection revisions prevents a stale tunnel
choice from being replayed after backend or gateway reselection.

The compiler intentionally requires committed exact kernel readback. Its
readiness digest is only an admission commitment in 9.5a; it is not described
as proof of encrypted packet delivery. Milestone 9.6 will replace that boundary
with authenticated, nonce-bound, two-ended live path evidence.

## Verification

`make encryption-fast-path-contract-test` checks cross-document drift, stable
ABI layouts, canonical order-independent coalescing, exact identity decisions,
policy/Service/egress revision precedence, explicit Native versus missing
authority, committed-readback refusal, active/new-flow switching, bounded
draining continuity, cross-identity lease rejection, expiry, revocation, and
strict Clippy.
