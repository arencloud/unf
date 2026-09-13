# ADR 0318: Required Policy-Tracked Reply Contracts

Date: 2026-09-13

Status: implemented; local verification complete; live qualification pending

## Gap and authority boundary

After the Native expiry/churn repair passed cl02 and matching-image retained
Kind (ADRs 0316–0317), Required return transport remained uncovered. A policy
can allow an initiating identity pair while denying new flows in the opposite
direction. The contract compiler previously omitted the denied direction
entirely, leaving an otherwise policy-tracked reply without Required transport.
The regression first fails with zero plans where one reply plan is needed.

The compiler now distinguishes new-flow policy provenance from reply transport
provenance. When a Required direction has an explicit denied policy fact, it
may obtain transport only from the exact opposite, uniquely allowed initiating
pair. The binding retains that pair as `replyTo`, its policy IDs/reason, and
the current policy revision. It never rewrites the denied policy fact. Both
directions still require exact public keys, lifetime, Node ownership,
bidirectional paths and kernel/path admission. Both-denied or unrelated pairs
gain no transport. Native requirements are not implicitly upgraded.

This is transport authority, not an established-flow claim. The actual packet
must independently pass the dataplane's policy/connection-tracking gate before
using it, including when an encryption lease exists. A new reverse connection
does not become authorized merely because reply transport is installed.

## Compatibility and bounded work

Contracts containing `replyTo` use schema 2 and the distinct
`unf.attested-encryption-path-contract.v2` digest domain. Contracts without
reply provenance remain schema 1 with unchanged serialized bytes, golden
digest and witness. The optional field is omitted, not serialized as null,
for the old shape. Strict nested decoding, schema-shape validation and
independent replay reject unknown fields, downgraded, stripped, mutated or
revoked authority. Legacy strict readers cannot consume schema-2 replies;
there is no claim of mixed-version reply support or negotiated downgrade.
Upgrade the complete fleet on its retained Native baseline before enabling
the new Required fixture. No encryption-map or persistent core-map ABI changes.

Reply identity pairs reuse the existing Node/epoch transport coalescing and
destination-prefix lookup. The regression covers four identity pairs replicated
across two peers: four decisions, two transports, with exact IPv4/IPv6 peer
selection. There is no interface per reply and no additional packet lookup.
Additional contract/proof work is bounded by existing capacities, not free;
this change has no measured throughput or resource-saving claim.

## Verification and remaining gates

Local tests cover the original red/green case; independent fact replay;
initiating-policy removal; missing or expired keys; missing bidirectional paths;
missing/ambiguous policy facts; strict/canonical wire shape; schema downgrade
and provenance mutation; unchanged v1 goldens; fleet distribution with idle
Nodes still dormant; coalesced dual-stack replicated reply selection; and
policy/revision denial before transport, including an existing encryption lease.

The full `unf-encryption` suite passes 127 tests (two privileged tests excluded
from that unprivileged run). Workspace tests pass 754 tests with 26 explicitly
ignored privileged tests; strict Clippy and contract guards pass. The boundary
guard's stale `In progress` expectation is corrected to the actual
`In progress — coverage repair` state, without closing the phase.
Evidence is retained under ignored
`.artifacts/p9-required-reply-*`; no credentials or private keys are included.

The live clusters still run qualified Native runtime `5ea1bd2`. This ADR does
not claim real Required reply traffic, same-Node locality, full Phase 9 closure,
or stabilization completion. Next: immutable candidate images; scoped cl02
policy-isolated Required TCP/UDP replies and unsolicited reverse denials with
ciphertext evidence; matching Kind only after cl02 passes; then remaining
locality/replica and complete lifecycle qualification, followed by S1–S5.

The preflight cl02 log review finds all six UNF Pods Ready with zero restarts,
438 bounded flow-history retention warnings in 20 minutes, and one rejected
reciprocal key-attestation publication that retained Node-local authority.
No ERROR is present in that window. This is not proof of key readiness: public
key/admission convergence must be checked before any Required activation.
