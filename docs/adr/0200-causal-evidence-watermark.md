# ADR 0200: Causal Evidence Watermark

- Status: Accepted and implemented for Phase 9.7a
- Date: 2026-09-10

## Context

Encryption diagnostics commonly collapse several different conditions into one
"tunnel down" signal. That loses the distinction between policy requirement,
assignment, local exchange, remote quorum, activation, expiry, collision, and
missing telemetry. Peer- or contract-labeled metrics restore detail by creating
unbounded cardinality and can expose topology. A bounded history that silently
evicts records creates a different failure: an empty query can look healthy.

## Decision

Phase 9.7a introduces the **Causal Evidence Watermark**:

- operational counters are one closed six-stage by nine-outcome matrix. A
  metrics exporter may use only those two enum dimensions; Nodes, peers,
  policies, contracts, epochs, addresses, and keys can never become labels;
- exact diagnostic history is separate, limited to 512 records, hash-chained,
  monotonically sequenced, and generation-fenced;
- checkpoint replay verifies schema, sequence continuity, eviction anchor,
  every retained record digest, retained counter lower bounds, total reported
  loss, and the newest generation before returning any state;
- retention eviction records both record and represented-observation counts;
  known upstream queue, source, decode, and clock loss is represented by an
  explicit marker with the exact omitted count;
- status publishes the newest completely verified sequence, head digest,
  retained count, eviction counts, upstream-loss count, and a direct
  `lossAffected` classification; and
- observations intentionally have no Node name, address, key, nonce, challenge,
  or consuming activation permit. A contract digest is a safe correlator only
  after requirement evaluation and is never metric label material.

The watermark does not infer health from silence. It says how far evidence is
continuous and whether the available window has known holes. Later Phase 9.7
slices wire this contract into agent/controller status and metrics, add
explanation/simulation, and exercise durable outage and upgrade recovery.

## Consequences

Operators gain one stable, low-cost metric surface and a precise bounded audit
surface. Cardinality is independent of cluster scale, while loss remains
visible after restart and after old detail is evicted. The history is diagnostic
evidence, not packet, route, key, or activation authority.

## Verification

`make encryption-operations-evidence-test` inherits the complete live Phase 9.6
gate, checks the closed metric domains and secret-free source boundary, and
tests stage/outcome semantics, loss accounting, capacity eviction, anchor-based
restore, mutation, generation regression, strict JSON, and strict Clippy.
