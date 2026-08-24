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

The canonical hash input is length-delimited and includes the complete sorted
label set. This is intentionally stricter than grouping only by application:
selector-visible metadata must not disagree for two Pods that share a numeric
identity.

Pod IP will become an index from observed packets to identity. It will not be the
security principal. The design deliberately includes cluster identity so later
multi-cluster connectivity does not assume globally unique Pod CIDRs.

Kubernetes `ipBlock` compatibility is an explicit address-based exception to
identity selection, not a new workload identity. Bounded IPv4 source addresses
are compiled into `POLICY_IPV4` while destination workload identity and normal
policy provenance remain mandatory. Native identity policy and compatibility
decisions still converge in the shared evaluator before lowering.

Identity BPF distribution and controller-epoch recovery are verified. Map pinning,
durable allocation, multi-controller ownership, and explicit unknown-identity
enforcement semantics remain open. See ADRs 0005 and 0006.
