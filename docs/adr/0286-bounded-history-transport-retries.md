# ADR 0286: Bounded History Transport Retries

Date: 2026-09-13

Status: qualifier repair implemented; full cl02/Kind qualification pending

## Observation

Runtime `cb59e90`, qualifier `77367c2`, stopped before Required migration on
cl02: the baseline history transfer timed out with exit 124 after receiving
114,683 bytes of incomplete JSON. This run did not reach ADR 0285's repaired
link-fault test. The failure trap removed the witness fixture; the controller
remained Native. No full lifecycle or cleanup qualification is claimed.

A separate subsequent diagnostic read returned 279,870 bytes and passed the
actual offline `unfctl encryption-history` verifier: revision 1,605,796,
512 retained records, and zero reported upstream observation loss. That
diagnostic used the Pod proxy and is not a substitute for the required
host-local witness capture or a successful uninterrupted platform gate.

## Decision

Shared history capture permits at most three transport attempts, with one
second between failures. Retain each raw attempt and record its exit code and
byte count. Verify only a successfully transferred response through the actual
offline CLI. Never retry a successful transfer whose content fails verification;
retrying that failure could hide corrupted evidence behind a newer checkpoint.
An exhausted transport failure remains a qualification failure. Evidence includes
the read-attempt metadata alongside the existing checkpoint hashes and explicit
retained-window-only completeness claim.

Controller and witness lookups use single bounded commands within their calling
retry loops, avoiding nested 15-attempt reads. On OpenShift, an unavailable
witness while its fixture is active fails the read; it cannot silently switch
to the Pod proxy during Required or causal qualification. The existing bounded
proxy path remains available only when the witness fixture is not active.
Individual commands have deadlines; this is not a new end-to-end latency SLA.

No runtime, encryption authority, history-retention limit, convergence deadline,
or content-verification rule changes. The pinned runtime remains `cb59e90`.

## Verification

`bash hack/verify-phase9-operations-continuity.sh` tests immediate success,
two failed transfers followed by success, exhaustion after three failures,
raw partial retention, exact verifier invocation count, immediate propagation
of verification failure, and read metadata in the evidence. Capture tests mock
transport and verifier orchestration, not cryptographic validation. Both
platform static gates include these regressions. The full lifecycle must still
pass on cl02 before the same images are qualified on fresh Kind.
`bash hack/verify-phase9-witness-read.sh` additionally exercises the actual
OpenShift read function with mocked commands: active-witness success, missing
active witness, permitted post-fixture fallback, and lookup/transfer failures.
