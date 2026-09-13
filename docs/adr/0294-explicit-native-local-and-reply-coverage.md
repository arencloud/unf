# ADR 0294: Explicit Native Local and Reply Coverage

Date: 2026-09-13

Status: implementation and local regressions verified; cl02 then Kind pending

## Decision

Repair ADR 0293's missing transport authority in the producer, not through a
permissive packet-path fallback. Deduplicate endpoint identities before local
pair enumeration, including hairpins. For each policy-allowed inter-Node fact,
cover both transport directions on the participating Nodes only when the
encryption model independently resolves that direction to Native. A reply's
transport record never grants permission for a new reverse connection:
per-packet policy and established-flow checks remain authoritative.

A Required baseline skips Native enumeration entirely. Selective Required
records are never overwritten or downgraded. Wire/map schemas, key lifetimes,
cryptography and missing-authority fail-closed behavior remain unchanged.

Stop before inserting beyond the remaining 65,536 decision slots and refuse the
whole cut instead of publishing partial coverage. This is bounded allocation,
not removal of the capacity limit: 257 distinct local identities alone exceed
the local Cartesian budget. Replica deduplication removes replica-driven work
from this stage, but no measured CPU or throughput improvement is claimed.

## Verification

The same-Node and isolated-return regressions failed on the old implementation
before repair. Five new tests cover locality/hairpin, policy-tracked replies,
policy-denied new reverse traffic, unknown-authority denial, deterministic
replica deduplication, early capacity refusal and unrelated denied remote pairs.
Updated existing assertions account for the additional local self record.

`cargo test --workspace` passes 737 tests with 25 specialized tests ignored;
strict all-target/all-feature workspace Clippy and formatting pass.
`hack/verify-native-transport-coverage-gate.sh` checks the actual probe boundary:
transport/exec errors and malformed responses cannot count as successful denial.

The portable live fixture requires exact runtime revisions, a digest-pinned
tools image, an empty owned Namespace and Native baseline. It isolates client
ingress and server egress, then requires 16 request/reply successes across
same/cross-Node, PodIP/Service, TCP/UDP and IPv4/IPv6, plus eight unsolicited
reverse denials. All listeners must first respond locally; cleanup requires
positive Namespace absence and agent convergence. cl02 runs before matching-image
fresh Kind. Neither live result is claimed in this implementation commit.

## Open boundaries

Required locality with identities replicated across local and remote Nodes,
and Required policy-isolated replies, need separate address/locality-bound
contract design and tests. Native-only coverage cannot close Phase 9. Operator
health, decision-count/resource measurements, load envelopes and S1–S5 remain
open. Retain historical passing gates and failed diagnostic attempts. No secrets,
private authority journals or packet payloads enter Git.
