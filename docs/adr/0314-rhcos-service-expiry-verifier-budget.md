# ADR 0314: RHCOS Service-Expiry Verifier Budget

Date: 2026-09-13

Status: cl02 candidate rejected; compatibility repair required

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
