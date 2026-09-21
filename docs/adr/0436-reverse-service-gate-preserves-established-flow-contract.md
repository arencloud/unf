# ADR 0436: Reverse-Service gate preserves the established-flow contract

Date: 2026-09-21

Status: failed cl02 attempt retained; test contract corrected, rerun pending

The `8dc7f3d` seven-test image passes its first six tests on cl02, then fails
the new reverse-Service assertion expecting a policy-revision increment alone
to invalidate an established reply. The actual return was PIPE, expected SHOT.
This attempt is failed, never a qualification, and was not advanced to Kind.

Inspection identifies a fixture/design-description error, not a demonstrated
failure of the documented connection timeout: ADR 0070 deliberately preserves
established TCP/UDP/SCTP witnesses across global policy-revision churn. The
existing shared regression `connection_state_is_protocol_bounded_and_survives_policy_churn`
asserts that exact behavior. Forcing revision equality would regress bootstrap
and ordinary connection continuity on unrelated Pod/policy changes.

ADR 0435's phrases "at the current policy revision" and "stale witnesses" are
therefore corrected: a reply requires an exact **live, protocol-time-bounded**
forward witness and an active nonzero policy configuration, not equality with
the witness's creation revision. The actual common policy and transport stages
still execute. No production authorization or timeout is weakened to pass a
test, and the connection implementation is unchanged.

The corrected exact test positively preserves revision-churn replies and
explicitly ages actual map timestamps beyond the protocol timeout. It requires
expired-witness denial, missing-witness denial, absent-policy denial, missing
transport denial, denied-forward/unsolicited-reply denial, and backend/wire
tuple preservation for IPv4/IPv6 TCP/UDP. Fixture uptime must exceed the timeout;
the test cannot silently skip that negative. The old failing evidence stays.

Failed image:
`quay.io/arencloud/unf-test-tools-dev@sha256:599e6d1cce11e19318a765e163f380997432c5f964895415ad81de9742719427`

Evidence: `.artifacts/p9-kernel-main-bridge-8dc7f3d-cl02`.
Result SHA-256 `c42d6d0b264c4fba10ad1465d498169921c4b6acba7d283a3a339948ca52b449`;
test log SHA-256 `6374ee1cbba8fa3dc6d937ae1706591728a06a9033271156670d3e1e3ea84921`.
Exact-UID cleanup passes. Production remains `45d85d5`, Ready/zero restarts,
with byte-identical journals. Current/retained regular/init logs contain no
ERROR or malformed/partial observations: 488 current WARNs and 7,045 retained
WARNs. Previously observed retention, peer/key retries and vanished-interface
attach observations remain recorded, not cleared or reclassified as healthy.

Strict agent Clippy and test compilation pass locally. Rebuild the corrected
source, repeat cl02 first, then identical-image Kind only after success. Actual
publisher/main-hook socket composition and L3/L4/L5/Q remain open.
