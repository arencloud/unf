# ADR 0005: Collision-checked identity admission and Pod-IP indexing

Status: Accepted for Phase 2

## Context

Phase 1 generated deterministic numeric IDs from canonical workload metadata but
did not admit them through a collision authority. Phase 2 needs a safe mapping
from packet IP addresses to identities before any policy can be enforced. Pod IP
must remain an index, not the trust principal.

## Decision

Maintain a controller-side `IdentityRegistry` with three explicit indexes:

- numeric identity to canonical metadata and reference count;
- Pod key to identity plus current addresses;
- IP address to owning Pod and identity.

Admission validates the entire update before mutation. It rejects ID zero, a
numeric ID already bound to another canonical key, and an address owned by another
Pod. Pod updates replace their prior binding atomically at this abstraction level;
deletion removes addresses and garbage-collects identities with no remaining Pod
references. Host-network Pod addresses are not eligible for workload indexing
because several Pods can legitimately share the node address.

## Alternatives

A central sequential allocator would avoid hash collisions but immediately adds
persistence and high-availability requirements. Treating a hash as collision-free
would allow two security principals to share policy state. Indexing only by IP
would make an ephemeral address the authority. These alternatives are rejected for
the first Phase 2 slice.

## Consequences

The current deterministic hash remains restart-stable, while collision admission
prevents it from silently becoming authoritative. The registry is still
in-memory; restart recovery, durable allocation, multi-cluster authority, and BPF
distribution remain explicit later gates. The same validation rules can precede a
future persistent allocator without changing dataplane identity types.

## Open questions

- durable identity allocation and collision recovery across controller replicas;
- dual-stack address lifecycle and stale watch ordering;
- explicit identities for host-network and external workloads;
- garbage-collection grace periods during API/watch interruption.
