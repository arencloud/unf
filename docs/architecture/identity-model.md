# Identity model

UNF identity represents authoritative workload metadata, not an IP address. The
initial tuple is cluster, namespace, service account, application/workload, and
labels. The dataplane uses `IdentityId(u32)` so it never compares Kubernetes
strings in a packet path.

During Phase 1, the controller computed a deterministic provisional FNV-1a ID from
canonical workload metadata. Zero is reserved for unknown identity. Phase 2 now
admits those IDs through a controller registry that detects canonical-key
collisions, indexes Pod IPs, rejects address reuse, reference-counts shared
workload identities, and garbage-collects deleted Pod bindings. The hash remains a
prototype allocator rather than a durable global authority.

Pod IP will become an index from observed packets to identity. It will not be the
security principal. The design deliberately includes cluster identity so later
multi-cluster connectivity does not assume globally unique Pod CIDRs.

Before enforcement, identity state still needs BPF map distribution, revision
acknowledgement, restart recovery, and explicit unknown-identity failure semantics.
See ADR 0005.
