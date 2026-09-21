# ADR 0393: Wait for the Terminal Pod Observation

Date: 2026-09-21

Status: observer regression verified locally; complete live gate pending

The first repaired-image cl02 PID-1 run proves the controller receives SIGTERM,
logs drain request/completion and exits zero without restarting. However, its
first API observation with `state.terminated` still has Pod phase `Running`.
The qualifier stops there and fails its subsequent `Succeeded` assertion.
This failed attempt is retained at
`.artifacts/p9-sigterm-6d71a30-cl02-isolated`; it is not a complete live pass.

The observer now waits for both container termination and a terminal Pod phase,
binding the before/after Pod UID. A failed terminal Pod is observed immediately
but cannot pass. Zero exit status, Completed reason, zero restarts, isolated
PID/network namespaces, both lifecycle log messages, successful log observers
and exact Namespace cleanup remain mandatory. Thirty bounded API observations
allow status propagation; this is not a thirty-second process-drain claim.

The shared jq predicates pass positive completion, two phase-lag cases, failed
terminal observation and ten negative mutations. The actual retained cl02
phase-lag observation is also rejected as nonterminal by the corrected filter.
Only the qualifier changes; immutable runtime remains `6d71a30`. Rerun the
complete gate on cl02 before matching Kind. Production locality and full
Phase 9 remain open.
