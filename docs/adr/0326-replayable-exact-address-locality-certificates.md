# ADR 0326: Replayable Exact-Address Locality Certificates

Date: 2026-09-13

Status: locality certificate verified locally; kernel consumption remains open

## Contract and authority boundary

`EncryptionLocalityCertificate` schema 1 binds the exact cluster, Node name/UID,
membership revision, identity epoch/revision, routing revision, local Pod CIDRs
and canonical address owners from ADR 0325's validated placement. Empty local
placement is explicit valid evidence with no matching tuple. Host-network and
non-workload address classes never become local workload authority.

The digest domain is `unf.encryption-locality-certificate.v1\0`. Its golden
fixture digest is
`a748225a38d3e68a34a60601e5dd9cf07a6b9bd1dc5e656eab9b575d0824cc50`.
Schema and nested wire objects reject unknown fields. A checksum only proves
integrity: `verify_against` reconstructs the entire certificate from separately
authenticated current placement/context and compares it exactly. A forged but
correctly rehashed identity substitution or incomplete cut is rejected.
The verified handle is not deserializable or mutable.

`local_tuple` resolves source and final destination address/identity through
two binary searches of the canonical address index. It returns the exact
workload owners, **not** an Allow verdict, Native disposition, fwmark, route,
device index or cryptographic lease. A same-identity remote replica, Service
VIP, unused address inside a local Pod CIDR, wrong identity or mixed-family
tuple does not match. Changed expected context fails explicitly. Consumers
must still prove policy authorization, Service/egress ownership and actual
local kernel attachment/routing before treating a packet as no-underlay.

## Bounded work

There is one stored owner per local workload address, not a local identity-pair
matrix. The 4,096-endpoint dual-stack test produces 8,192 address records and
checks lookups across that cut. Digest serialization streams into SHA-256,
avoiding a second complete JSON buffer; an independently buffered encoding
must produce identical bytes/digest. These are structural storage/allocation
properties, not measured deployment CPU, RSS, latency or throughput results.

## Verification and compatibility

Twelve focused tests cover local/remote replicas, both IP families, final
addresses, all context coordinates, Pod movement/deletion, UID reuse, identity
and Node replacement, rehashed substitution/incompleteness, malformed shape,
strict wire decoding, permutation invariance, empty/host-only placement,
excluded address classes, the frozen digest and endpoint-budget cardinality.
The all-features workspace passes 770 tests, with 26 explicitly ignored;
strict all-target/all-feature workspace Clippy and formatting pass.

No current plan envelope, fast-path ABI, map, route, key, journal, release pin
or runtime default is changed. Both live fleets remain on `67c2772`; this
library certificate is not yet distributed or consumed by the packet path.
Its future wire/map integration requires explicit capability/version and
restart migration, not silently adding fields to existing authority.

cl02 preflight inspects controller, every agent and installer logs: all five
Nodes/six UNF Pods are Ready with zero restarts; proof/plan, Service-map, key
and retention warnings remain recorded. Kind's recent bounded logs show no
warning, but retained current/rotated agent logs still contain earlier
proof/plan retries and the previously recorded telemetry/egress request
failures. The expanded Kind read covers 57,141 lines / 33,619,305 bytes.
No ERROR/panic/OOM/verifier rejection is found in the retained windows. This
does not claim lossless history, a clean operational history or a new platform
feature qualification. Raw logs remain ignored, without private key readback.

Next: L3's kernel attachment/route ownership, compatibility and banked consumer;
then cl02 locality/replica validation before matching Kind, followed by complete
Phase 9 lifecycle requalification. L4/L5/Q and S1–S5 remain open in the
[locality closure plan](../development/phase9-required-locality-plan.md).
