# ADR 0394: Isolated Service Shutdown on cl02 and Kind

Date: 2026-09-21

Status: isolated PID-1 gate verified; fully configured fabric recovery pending

Runtime `6d71a30984fa130f66c31bbfabdd170a3e63eb59` (ADR 0392), qualified by
`052155c` (ADR 0393), passes cl02 first and persistent dual-stack Kind second.
Both use the same anonymously pullable immutable images:

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:1dbd2fca0303ae1830805512fdf056287efc40baf56dcabdaa01a1db96aec2ca`.
- Agent: `quay.io/arencloud/unf-agent-dev@sha256:b08e4b2ec8f0d0de56035f733273ca6328d3dfa81f860207b71e2ca43c454790`.

CNI SHA-256 remains `812b0e33a46ea705c64af35fe6cf96598bb2dd0bfdad6537bd5934509ff024b3`;
BPF remains `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`.
Core map ABI 15 and encryption ABI 2 are unchanged.

Each platform runs four separate non-root, read-only-root-filesystem Pods with
no host PID/network namespace, capabilities or service-account token mount.
The offline controller and capability-only agent each receive SIGTERM and
SIGINT as PID 1, after exact embedded-version and executable-path checks.
All eight processes log shutdown request/completion and finish with exit code
zero, Completed reason and zero restarts. Log observers succeed; both owned
Namespaces disappear and every test UID retires from the real CNI journals.
Expected offline/capability-only warnings are retained; fixture logs have no ERROR.

Before/during/after live UNF logs are reviewed. The final cl02 window retains
537 warnings, mainly bounded flow/topology history, path-proof assistance,
status acknowledgement and reconciliation/watch retries; Kind retains 29
plan-sync and four proof-assistance warnings. No ERROR is observed. Both
existing fleets finish fresh/converged (cl02 policy 467 / Service 221; Kind
policy 53 / Service 19), Ready with zero restarts, still on Native `8db97bb`.
These isolated probes do not upgrade or restart the live fabric.

cl02's CNI count changes from 118 to 116 during the wider observation window.
The only removed preexisting records are two old metrics-server sandboxes:
Node .200 `1e5d93a3…` and Node .203 `f189faf6…`. Exact CRI-O stop/removal logs
independently identify the OpenShift monitoring Pods; all remaining records
are unchanged. Direct sandbox inspection is already NotFound. Strict SSH on
.203 rejects a changed host key; this is preserved, not bypassed. Authenticated
`oc adm node-logs` supplies that Node's positive identity/removal evidence.
Kind's preexisting attachment remains byte-identical. No state is reset.

Evidence: `.artifacts/p9-sigterm-6d71a30-{cl02,kind}-terminal` and
`.artifacts/p9-sigterm-{cl02,kind}-*`. Both compact result summaries have SHA-256
`3cd428fbb141c18749f4d9650d679995c6dd755367a161f2fb2706f30c4b1eb7`;
that schema omits platform identity, so the independent Pod/Node metadata and
log bundles, not the identical summary hash alone, establish the two runs.
The red SIGTERM, Pod-proxy and terminal-phase failures remain retained.

Next: guarded live rollout and configured recovery/traffic validation, cl02
before matching Kind. `liveFabricShutdownQualified` remains false. L3 packet
consumption, L4/L5/Q and S1–S5 stay open; no release pins or credentials change.
