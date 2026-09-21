# ADR 0410: Preserve the OpenShift Key-Progress Drain Failure

Date: 2026-09-21

Status: image/rollout checks pass; encryption runtime qualification not verified

Source `7fbf7ee` builds and publishes with exact embedded revision, public digest
and unchanged production BPF (`d8551daa…05a27d`, core ABI 15 / encryption ABI 2):

- Controller: `quay.io/arencloud/unf-controller-dev@sha256:a31003996445600c1e3aaf121f67c482f717d5651a528d10738f453866be87ab`.
- Agent/CNI: `quay.io/arencloud/unf-agent-dev@sha256:6caab546b69ab6d59189aae34e7f6f21e94469ac1c7869da0cb6b3c4f8202c08`.
- Installed CNI SHA-256: `4825143419c747fb76d0c486fc3edb94ba06adb0af05e8e4c5c214b6a7f3b01c`.

The cl02 isolated PID-1 tests verify all four controller/agent SIGTERM/SIGINT
exits, zero restarts and exact cleanup. Guarded controller and five-agent rollout
then verifies provenance, each installed CNI hash and the real CNI protocol.
All runtime Pods become Ready with zero restarts; fresh reports converge at
policy 393 / Service 181 under the new controller incarnation. All five CNI
journals and their 116 records remain byte-identical. No key journal, history,
map bank or baseline is reset; baseline remains Native.

## Failed key-lifecycle boundary

The better cause-chain logging added in ADR 0409 exposes twelve activation
failures in the staged log window: `durably activate mutually attested key
epoch: epoch drain window is invalid`. The former issuance-floor early exit is
not the only obstacle. The key authority currently refuses activation whenever
the full requested drain interval would exceed the predecessor's sealed expiry,
even with a still-valid, completely attested successor.

Do not extend an expired predecessor's lifetime, clear the key store, discard
the successor, or call Ready status successful key rotation. Reproduce this
boundary and preserve bounded expiry plus positive zero-state retirement in
the repair. Configured-restart and Required traffic/ciphertext qualification
have **not** been completed for this runtime. Do not advance it to Kind.

## Log and platform observations

All UNF regular/init logs are captured, including all eleven retiring streams.
An authenticated read-only node-log API capture also reads exact current-Pod CRI
paths, including retained files, without bypassing SSH host-key checks. Before
rollout, retained history contains 5,799 warnings across 26 categories; after
rollout the staged retained capture contains 344 warnings. Both have zero ERROR,
partial or non-JSON lines. Startup qdisc-exists, authority/proof retries and
bounded-history warnings are retained, not silently classified as health.

The pre-existing Insights upload timeout and network-operator requested/applied
multi-network mismatch from ADR 0375 remain present. Neither configuration is
mutated by this qualification.

Evidence: `.artifacts/p9-key-progress-7fbf7ee-cl02-{terminal,rollout}` and
`.artifacts/p9-key-progress-cl02-{before,staged}-{logs,journals,cri}`. Staged
message-summary SHA-256: `d8188ede9a13d2443644361e4b826ede5802ed7b88abf08f12b1ea0a1a06e8e4`.
Rollout Pod snapshot SHA-256: `b8daf3f3c889309726c343cb6adf532fe23ebe65d4d6bb401a6d5551b44dcafb`.

cl02 now runs `7fbf7ee`; Kind remains on `6d71a30`. No release pin, platform
qualification, L3/L4/L5/Q or Phase 9 completion status is promoted.
