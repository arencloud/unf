# ADR 0320: Required Reply cl02 First Failure

Date: 2026-09-13

Status: live reply qualification failed; retained Native cleanup verified

Runtime `67c2772` passes the serial cl02 deployment without an agent/controller
restart, BPF verifier rejection, journal reset or frontier reset. The unchanged
RHCOS-qualified BPF object remains in use. Deployment evidence SHA-256:
`0985605898b2d5970db86a6cfe082fd244db7ed9861eb262f6d341496b4cec28`.

Qualifier `ec8fd5c` admits all 32 fixture policy outcomes at revision 459.
Both workers then admit generation `1789313719125`, epoch 871: the client has
the ordinary schema-1 forward contract; the server has schema 2 with exact
`replyTo` provenance. Policy-isolated initiating identity `2847593581` and
replying identity `3458476097` retain the initiating policy IDs and revision.
No reverse new-flow permission is synthesized.

Eleven Required-intended request/response probes complete across dual-stack
PodIP and Service paths. The twelfth probe, UDP from the Required client to
IPv6 Service `fd02::f60b`, translated port 53 → 5353, fails. The Native control
matrix and unsolicited reverse denials have not run; the complete gate fails.
There is no claim of verified ciphertext or a root-cause attribution from
these partial successes.

## Evidence gap and correction

The first gate's failure trap collected fixture JSON but deleted its Namespace
before copying the capture. The lost packet file cannot be reconstructed.
The later bounded flow-history window has no matching failed-tuple entries;
absence there is not evidence that the packet was never observed. Diagnostics
remain under ignored `.artifacts/p9-required-reply-67c2772-*`.

The trap now explicitly stops/flushes and retains failed-run capture evidence
before Namespace cleanup, without treating it as a passing ciphertext result.
Every probe records protocol, endpoint, port, time and exit classification.
Tests preserve a mocked failed-run packet file and reject observer failure;
the existing capture-loss/crash/timeout tests remain mandatory. These changes
repair evidence collection, not the dataplane failure.

All current UNF container/installer logs are reviewed. They contain no ERROR,
panic, OOM or verifier failure in the retained window. They do contain startup
admission, key catch-up, reciprocal proof/plan retries, one Service selection
contract synchronization warning on a non-fixture Node before this test, and
the already tracked policy/named-port/retention warnings. Neither that Service
warning nor key rotation is an established cause of this UDP failure.

The owned fixture Namespace is absent afterward. All five public admissions
converge to Native generation `1789313948293`, with explicit `epochCount=0`
and `transportCount=0`, and the controller reports all agents converged.
No map or journal is cleared. Kind remains on qualified Native `5ea1bd2` and
does not receive the candidate until cl02 passes.

Next: reproduce with retained underlay and paired inner-packet diagnostics,
attribute the precise UDP failure, add its regression and repair it. Then
repeat the full scoped gate on cl02 before matching Kind. Required locality,
replica/lifecycle qualification and S1–S5 remain open.
