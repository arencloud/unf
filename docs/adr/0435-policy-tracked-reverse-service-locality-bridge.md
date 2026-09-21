# ADR 0435: Policy-tracked reverse-Service locality bridge

Date: 2026-09-21

Status: implemented and locally checked; immutable kernel qualification pending

The enforcing ingress reverse-Service path previously rewrote a reply and
returned PIPE before policy, encryption and locality finalization. A Service
connection is created before forward policy, so that map entry alone cannot
authorize a managed reply.

After the exact reverse lookup and successful rewrite, the new bridge resolves
current identities using the actual backend and client, never the rewritten
VIP. When both are managed it requires an exact, unexpired forward connection
witness at the current policy revision. Missing/stale witnesses drop before
the common policy tail. That tail re-evaluates policy/stateful return before
the normal locality/transport finalizer; policy permission alone cannot skip
ordinary transport authority when the bank is absent.

A private per-invocation reverse flag preserves this transaction's ownership:
it neither seeds a new frontend connection nor borrows an independent source
or gateway egress NAT. Locality input retains backend ownership while ports
come from actual rewritten wire bytes. Non-enforcing egress reverse handling
is unchanged. This does not establish complete remote/DSR composition by source
inspection; live checks are still required.

The new root-only regression runs IPv4/IPv6 × TCP/UDP through the actual main
classifier. It asserts positive translation, backend identity and wire ports,
missing/stale forward-witness denial, current stateful return despite reverse
deny, missing transport denial, and denied-forward/unsolicited-reply denial
even when a Service mapping was created. The expanded immutable diagnostic
requires seven exact tests, retaining all previous cases and adding this test
plus the existing Service translation/churn regression.

Local checks: 909 workspace tests pass, 29 privileged/platform cases ignored;
agent test compilation, strict all-target agent Clippy, main BPF release
compilation, formatting and shell syntax pass. Ignored tests have **not** been
claimed as kernel passes. Rebuild this source and qualify cl02 before matching
Kind. No production image, map, journal or release pin changes in this slice.

Actual main-hook selected-bank sockets, full publisher/writer composition,
mixed local/remote replicas, crash cleanup and restart continuity remain open.
L3/L4/L5/Q and stabilization are not promoted.
