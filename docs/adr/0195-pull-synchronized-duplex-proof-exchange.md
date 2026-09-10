# ADR 0195: Pull-Synchronized Duplex Proof Exchange

- Status: Accepted and implemented for Phase 9.6b
- Date: 2026-09-10

## Context

The Causal Duplex Path Quorum defines exact endpoint evidence, but production
collection also needs an atomic source of challenge work. Per-Node mutable
queues could mix plan generations or retain a healthy endpoint's evidence after
its peer, contract, or topology has changed.

## Decision

Phase 9.6b adds the **Pull-Synchronized Duplex Proof Exchange**:

- the active complete fleet-plan generation is the sole challenge source;
- one atomic replacement issues every contract/plan round or none, and same-
  generation source mutation is equivocation;
- each agent can retrieve only assignments naming its current Node name/UID;
- every GET and POST repeats the existing TLS, bearer TokenReview, Pod UID,
  service-account, audience, Node placement, and authoritative Node UID checks;
- evidence is routed by its unguessable round digest into an append-only ledger;
- generation advance clears every unfinished and completed old proof;
- an expired round can be renewed without changing plan authority; and
- receipts are returned only to involved endpoints and only while current.

This pull model is demand-driven and fixed by the already published causal cut,
so idle Nodes create no probes and controller retries do not multiply tunnels
or mutable health objects.

## Consequences

The controller now exposes authenticated assignment, proof-ingestion, and
receipt endpoints. Agent-side live challenge execution and the final consuming
activation join remain Phase 9.6c; no receipt is described as reusable map
authority.

## Verification

`make encryption-path-runtime-test` inherits the live Phase 9.5 and 9.6a gates,
tests generation fencing, endpoint scoping, renewal, old-evidence removal, and
current-agent membership, then applies strict Clippy to the domain and
controller.
