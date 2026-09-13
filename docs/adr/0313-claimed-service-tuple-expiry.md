# ADR 0313: Claimed Service-Tuple Expiry

Date: 2026-09-13

Status: local kernel regressions pass; cl02 rejects verifier complexity (ADR 0314)

## Decision

Repair ADR 0312's expired reverse-key obstruction in the packet path. First
attempt exclusive insertion. On failure, inspect only that exact incumbent;
require the known schema, matching forward/reverse tuple and a timestamp
strictly older than its protocol lifetime. Claim the observed timestamp with
one compare-exchange before removing the slot, then attempt one exclusive
insertion. Live, future-dated, mismatched and already-claimed owners are not
permission to overwrite. No scan, periodic broad clearing, larger limit,
longer timeout or policy/encryption fallback is introduced.

An old paired key is retired only when all owner fields and the observed
timestamp still match. Competing touches advance time in place, rather than
replacing the complete value and potentially overwriting a retirement or a
different peer. A competing monotonic touch counts as activity; ordinary
same-flow CPU contention does not itself require a drop. The maximum u64
timestamp is reserved for a claimed mutation and cannot authorize traffic.
Successful reclaim leaves the old counterpart for its independently checked
lazy expiry, which must preserve a different successor owner.

Encrypted DSR is a deliberate exception to immutable owner fields: its exact
Required flow converts to reversible NAT. It claims the current forward owner,
publishes the checked reverse row, changes only the DSR/encrypted-NAT flags,
then releases the timestamp. Failed reverse admission restores the original
timestamp and does not overwrite the conflicting owner. The broad privileged
suite caught this interaction with the initial ownership guard; that failing
attempt is retained, and the repaired encrypted-DSR test passes.

One non-persistent, single-entry per-CPU scratch map stores a 104-byte cold-path
incumbent copy. Direct key-field construction keeps the complete call chain
within the kernel stack bound. Persistent map shapes, wire schemas, policy
authority and encryption epochs remain unchanged. This is not an unbounded
connection-capacity or fully atomic two-key-map claim: LRU capacity eviction,
active reverse-tuple collisions and broader churn still need the defined
stabilization/load-envelope qualification.

## Verification

The original kernel test failed against the old object at expired-slot reuse.
The repaired test covers IPv4/IPv6 TCP/UDP, live-owner refusal, conflicting
peer refresh, retirement-marker refusal, expired complete/partial pairs,
delayed old-forward cleanup preserving a successor, and translated replies.
Four barrier-started threads issue 256 forward/reverse kernel test-run calls
per family/protocol case against shared live maps. No contention drop is
accepted. A unit test mutates each immutable owner field independently and
proves only activity timestamp changes retain ownership; expiry-boundary and
retirement-marker checks remain explicit.

- Workspace: 748 passed, 26 explicitly specialized ignores; strict workspace
  all-target/all-feature Clippy and formatting pass.
- Service transaction suite: nine privileged kernel tests pass, including the
  new expiry regression and existing bank/rollback/selection checks.
- Broader DSR runner: 19 self-contained privileged agent tests pass. Its
  separately configured WireGuard wire-engine fixture also passes dual-stack
  marked rendezvous, peer loss, expiring response service and fresh recovery.
  The runner now invokes that fixture instead of incorrectly invoking its
  role-dependent test without environment configuration.

Evidence is ignored under `.artifacts/s1-service-expiry-*`; final suite logs
are `workspace-final.log`, `clippy-final.log`, `service-kernel-final.log` and
`dsr-full-final.log` with that prefix. Earlier verifier failures at 688, 576
and 544 bytes remain failed attempts, not qualified objects. The final object
loads under the real kernel verifier using the normal pinned build command.

The compiler investigation also rejected the initial LLVM-library mismatch
hypothesis: matching the exact Rust LLVM library did not fix the invalid IR.
The pinned BPF compiler emitted an i8 branch for the intrinsic's boolean tuple
result. Comparing the returned integer with the expected operand avoids that
lowering defect while preserving CAS semantics. The final build uses the
ordinary linker and no modified system library; a project-local experimental
linker remains ignored and is not required. The pinned nightly intrinsic is
explicit, with kernel load tests mandatory for future compiler changes.

## Immutable candidate publication

Runtime source `5505d00710f7f7947f770456cdaeb9654af04a85` is built and
published to the development repositories. Both isolated images report that
exact revision through `/v1/version`. Both packaged BPF objects hash to
`90b1ccad01f22af45e541ca1cf400d537b6026a72f101958bfc1f3591e95b0bd`;
the prior object is archived separately, not packaged.

- Controller manifest: `ed6467f3c09ac2e5756bc74c0a77df892dec38b2f39963028798b5594c7bc506`.
- Agent manifest: `3bc02e761dfd23ff98a0bcd5fdb4d76abecac9e1359b2b8f7d15e6c43a6d1242`.

The release record remains OpenShift-first with full Kind qualification pending.
The pre-rollout 20-minute log review finds all six cl02 UNF Pods Ready with zero
restarts, no structured ERROR entries, 452 bounded flow-history retention
warnings and one rejected reciprocal-key attestation warning. Those warnings
are retained as observations, not evidence of clean overall cluster health.
Raw logs and build/provenance evidence remain ignored under
`.artifacts/s1-expiry-5505d00-*`.

## Next

Commit the immutable release pins before deployment, deploy cl02,
inspect every UNF container's logs and run the adopted Native/churn gate.
Only after cl02 passes may retained Kind receive the same images. No live
result, CPU/throughput saving, Phase 9 closure or S1–S5 completion is claimed
by this implementation milestone.
