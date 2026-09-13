# ADR 0314: RHCOS Service-Expiry Verifier Budget

Date: 2026-09-13

Status: minimal copy repair passes isolated cl02 loading; runtime qualification pending

## Evidence

Runtime `5505d00`, release qualifier `79b6e0b`, passes local kernel regressions
but fails the cl02 rollout. The first replacement agent's retained previous
container log reports `BPF program is too large. Processed 1000001 insn`, a
1,000,000-instruction verifier limit, 27,168 total states and 20,938 peak states.
That attempt reports 10,216,585 microseconds of verification. Its retained
trace includes byte-wise copying of the 104-byte Service incumbent. This is
verifier analysis complexity, not one million instructions executed per packet.

Liveness timeouts/restarts preceded the captured rejection. The deployment
was stopped after it reached three Nodes; its Phase 9 staging check observes
the management API before BPF attachment and therefore did not contain the
failure to the first Node. The two untouched agents remained Ready. Restoring
the previous agent image is in progress, preserving all maps, journals and
authority frontiers. The candidate controller is unchanged by this recovery.
No Native traffic result or Kind qualification exists for this candidate.

Ignored evidence: `.artifacts/s1-expiry-5505d00-cl02-failed-logs/`,
`rollout-events.json`, `cl02-deploy.log` and `rollback.log` with the same
`.artifacts/s1-expiry-5505d00-` prefix. Early log snapshots lacked the rejection;
do not infer an unsupported CAS opcode or blame key authority from those alone.

## Decision

Reduce verifier work without changing expiry, immutable ownership checks,
persistent ABI or the kernel budget. Examine fixed-width, branch-bounded
owner comparison and incumbent copying. Reproduce and load the exact object
in an isolated cl02 network/mount namespace before another CNI rollout.
The fixture must not attach to host interfaces, use live pin paths or carry
cluster credentials. A local-kernel pass cannot substitute for RHCOS evidence.

Strengthen rollout fault containment separately: pre-attachment API exposure
is required for the fleet barrier, but a restarted or terminated new agent
must stop further Node transitions. Retain full fleet convergence as the exit
gate, rather than falsely requiring every staging agent to be Ready before
the fleet can admit it.

## Minimal repair and isolated cl02 result

Keep the original field-by-field ownership comparison and all claims intact.
Copy the incumbent through thirteen constant-offset, aligned, volatile u64
loads/stores instead of allowing LLVM to lower the aggregate copy to a byte
loop. Compile-time size/alignment assertions fence this ABI-specific operation.
The attempted u128 comparison exceeded stack bounds; the attempted outlined
word-wise comparison exceeded verifier instruction bounds. Neither is retained.

The same credential-free observer loads the twelve tail programs, populates
its new dispatch map, then loads both roots. It never pins maps/programs or
attaches an interface. It runs on cl02 worker `.202` in a non-host-network,
non-host-PID Pod with no host mounts or service-account token, bounded at two
CPUs/512Mi memory. The observer is compiled against the runtime builder's Aya
dependency and uses the ordinary loader, not a relaxed verifier.

- Original object `90b1ccad01f22af45e541ca1cf400d537b6026a72f101958bfc1f3591e95b0bd`
  reproduces rejection of `unf_observe_ingress` at 1,000,001 instructions.
- Repaired object `d8551daad5f6222a8b9ddd7b3e7ed5d869bdea53c99b1e8c692f8ec0c205a27d`
  loads all fourteen programs in 4,111 ms, including ingress in 1,412 ms and
  egress in 1,724 ms. These are one fixture's load times, not packet throughput.
- Red log SHA-256: `4df3e69618ec0225f1592aa85e23346b7e5c0714d826f123a10c35538d5a4ac2`.
- Green log SHA-256: `84cb01a48b8748b84ba3a3d35dd70b6f7f8b18fd1d3089d3828fed284b5d9b98`.

The first streaming observer lost its API connection while returning a verifier
trace and is not counted as a result. The complete red and green attempts use
bounded in-Pod execution, save logs, and explicitly report exit 1 and exit 0.
Evidence and observer source/binary remain under `.artifacts/s1-verifier-*`.
Local nine-test Service and nineteen-test agent kernel suites pass, including
the separate dual-stack WireGuard wire-engine fixture. New immutable runtime
deployment, logs and actual traffic checks still have to pass cl02 before Kind.

Workspace verification passes 748 tests with 26 specialized ignores, strict
all-target/all-feature Clippy and formatting. The isolated Namespace is
positively absent after cleanup.

All three previous-image agents recovered Ready with zero restarts. Existing
maps/journals remain intact; the two untouched agent Pods were not replaced.

## Rebuilt immutable candidate

Source `5ea1bd2b759915edae0fe674863c5b3e9ebefb24` is published to the
development repositories. Both isolated image APIs report that exact revision;
both packaged objects match the repaired `d8551daa…` SHA-256 above.

- Controller: `2f3a4e4e9265e319d2fde9f60c971188e7120910d89d222e6332826b34397846`.
- Agent: `ddafaa1489a8ff426f729ae744483089a1626e11d0fd59bd67d75661de9484a3`.

The pre-rollout public cut has five receipts at generation `1789309599511`;
all five public Node journals were captured without accessing private keys.
Release pins retain OpenShift-first ordering and pending full Kind evidence.
ADR 0315's fault guard applies to this next rollout. These publication and
preflight facts are not a runtime traffic or Phase 9 completion claim.
