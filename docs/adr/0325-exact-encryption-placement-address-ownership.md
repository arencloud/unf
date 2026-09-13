# ADR 0325: Exact Encryption Placement Address Ownership

Date: 2026-09-13

Status: local implementation; no locality bypass or live rollout

The next Required locality slice cannot use an identity-wide Native decision:
one identity may have local and remote replicas. The existing Kubernetes
encryption projector validates CIDR membership but discards workload addresses
and accepts two different workload UIDs claiming the same address. A new
regression demonstrates that acceptance before the repair, including replicas
sharing one identity. Its red result is retained locally.

The shared placement projector now preserves a canonical exact address index
binding IP address, workload UID, identity and Node UID. Duplicate IPs are
rejected across UIDs and within one workload. Host-network workloads remain
excluded. Existing readiness, disjoint-Node CIDR, IPAM and reserved proof-beacon
checks remain mandatory. Endpoint and total-address budgets are checked before
record expansion; the address budget is 65,536, not an unlimited-scale claim.

The new opaque `KubernetesEncryptionPlacement` exposes read-only facts through
a placement-only API. It does not enumerate policy identity pairs, produce
WireGuard paths, read keys or emit transport decisions. Native and Required
projectors share the same validation. Their existing contract wire formats,
digests and BPF ABI do not change. Valid placement remains permutation-stable.

Local tests cover duplicate owners with same/different identities, duplicate
addresses, host-network exclusion, shuffled input, overflow and a 4,096-endpoint
dual-stack cut producing exactly 8,192 address records. This is a cardinality
check, not a runtime resource benchmark. All 131 encryption tests pass (two
privileged tests ignored), as do strict crate Clippy and formatting. The
all-features workspace run passes 758 tests, with 26 explicitly ignored.

cl02 preflight reads all UNF agent/controller/installer logs. All five Nodes
and six UNF Pods are Ready, with zero restarts. The retained window has no
ERROR; proof/plan synchronization, Service-map synchronization, key catch-up
and history-retention warnings remain visible. No cluster image/configuration
is changed by this slice.

Next is a versioned locality certificate replayed against this exact placement,
then the separately verified consuming/kernel boundary. Placement alone does
not establish a physical no-underlay path or authorize plaintext. The detailed
[locality closure plan](../development/phase9-required-locality-plan.md) tracks
implementation, cl02-first/Kind validation and full lifecycle requalification.
Phase 9 and S1–S5 remain open.
