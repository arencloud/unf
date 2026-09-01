# ADR 0105: Distribute and transactionally activate selection contracts

**Status:** Accepted and implemented for Phase 7.3

## Context

ADR 0104 defines a canonical, independently replayable Network Behavior
Contract, but deliberately stops before transport and activation. Phase 7.3
must ensure that an authenticated agent receives only its Node projection,
admits only capabilities it actually provides, never acknowledges a digest it
did not read back, and can recover the exact state that won a partial service
transaction. This must remain compatible with controllers and agents that
predate the contract without implying that advanced packet behavior exists.

## Decision

The controller exposes authenticated `GET /v1/state/service-selection` and
compiles the complete schema-v1 contract from one authoritative Service
snapshot, topology revision, Node UID, zone, and the capabilities supplied by
the requesting agent. The Node identity comes from the authenticated Pod
placement and watched Node state; a caller cannot select another Node. Schema
selection is explicit on both the version preflight and contract request.
Schema 0 remains the additive legacy representation, while unknown newer
schemas fail closed.

The Phase 7.3 agent advertises only `StableHash` and `Nat`. It fetches the
Service snapshot, authenticated local Node snapshot, and per-Node contract,
then independently runs the ADR 0104 verifier against all three before any
stage. Missing contract transport is a safe legacy fallback only for default
selection intent; advanced intent cannot activate or converge without a
verified contract.

Verified contracts use an agent-owned two-bank userspace transaction. The
agent writes the inactive bank, reads it back, recomputes the source, Node,
capability, invariant, failure-envelope, plan-digest, and contract-digest
checks, and only then advances the userspace activation pointer as part of the
existing service transaction. A failure restores the previous stage, service
and NodePort activation pointers, last-known-good checkpoints, and pending
files. The old inactive contract is retired only after success.

The durable selection checkpoint is a strict schema-v1 JSON object beside the
versioned service checkpoint. It contains the exact contract, normalized
authenticated Node snapshot, and active bank, is written as an owner-only
regular file, and is committed through the same prepared/current crash model.
Startup selects only a checkpoint whose epoch and Service revision match the
service state that actually won. This repairs a crash between service and
selection commits, reconstructs cold userspace state, and rejects mutations,
unknown fields, weak ownership, stale revisions, or incomplete Node binding.
The primary-CNI rollback removes current, pending, and exact temporary
selection files along with the owning service state.

Agent status schema v7 carries negotiated selection schema, desired/applied
contract revision and digest, and active bank. The controller validates their
shape and declares a Node converged only when both acknowledgements equal its
current per-Node digest. Nodes with no Service frontend have no selection-state
convergence requirement. Negotiating contract schema 0 projects pre-selection
status schema 6 so either binary ordering remains runnable; the controller
accepts such live reports only with no selection schema or acknowledgement, and
they cannot satisfy convergence where a contract is required.

Phase 7.3 does **not** change the persistent BPF ABI or packet behavior. The
selection banks are userspace admission and recovery state. Milestone 7.4 will
define fixed-width BPF maps and real-packet locality/topology enforcement; an
ABI increment must not precede that consumable layout.

## Consequences

- Contract transport, admission, checkpointing, rollback, recovery, and
  convergence are exact and independently testable before packet enforcement.
- Old controllers remain usable for default intent, but cannot silently enable
  or acknowledge advanced intent. Old agents remain packet-safe under a new
  controller but do not satisfy contract-required convergence.
- A topology-only revision can produce and activate a new digest without
  needlessly rewriting existing Service BPF maps.
- The checkpoint stores bounded Node addresses in addition to the contract so
  a cold restart can rebuild the existing host service state without network
  access.
- Maglev and DSR remain unavailable because the Phase 7.3 agent does not
  advertise those capabilities; their independent milestones must add and
  qualify them.

## Verification

`make service-selection-state-test` covers schema negotiation, deterministic
authenticated per-Node projection, capability rejection, exact convergence,
private digest-bound checkpoint prepare/commit/replay, mutation and unknown
field rejection, adjacent controller compatibility, inherited contract tests,
and strict Clippy.
