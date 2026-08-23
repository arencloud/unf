# ADR 0004: Numeric metadata-derived network identity

Status: Accepted for Phase 1; allocator is provisional

## Context

IP addresses change and may overlap across clusters. The fast path cannot compare
Kubernetes strings, while operators need metadata-rich explanations.

## Decision

Represent the fast-path principal as `IdentityId(u32)`. Resolve it from
authoritative cluster/namespace/service-account/application metadata. Treat Pod IP
only as an index. Reserve ID zero for unknown identity. Use a deterministic hash
for Phase 1, with collision admission checks required before enforcement.

## Alternatives

Use IP as identity, centrally allocate every ID immediately, or put hashes/labels
directly in BPF maps. The first cannot support overlap, the second is premature,
and the third increases map and packet-path cost.

## Consequences

Userspace must retain ID-to-metadata mappings and handle lifecycle, collision, and
revision state. Multi-cluster cluster IDs can be incorporated without requiring
unique Pod CIDRs.

## Open questions

Allocation authority, collision recovery, restart persistence, GC, external/FQDN
identities, and cross-cluster federation.
