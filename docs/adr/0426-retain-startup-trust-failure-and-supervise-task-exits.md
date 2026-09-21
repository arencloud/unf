# ADR 0426: Retain startup trust failure and supervise task exits

Date: 2026-09-21

Status: cl02 failure retained; corrective implementation verified locally;
paired real-process qualification pending

The `kernel-agent-startup` gate for `01aba67` fails on cl02. The diagnostic image
has no system CA bundle. The real agent establishes early ownership and the
schema-5 CNI gate, but `reqwest::Client::new()` panics while constructing its
unconfigured controller client. The supervised dataplane task therefore never
sends its explicit failure. Main previously watched only signals/failure messages,
not completed tasks, so the fixture reaches its 15-second timeout. This is not
a passing startup or packet test. Kind was not attempted.

Failed immutable image:
`quay.io/arencloud/unf-test-tools-dev@sha256:afa829337163882acd7e3b1ea086d54f9dbd976264747f7d71ef5fe7b6784d58`

Evidence: `.artifacts/p9-kernel-agent-startup-01aba67-cl02`.
Result SHA-256: `76c0ebf4ccd5a16c0c8c0f10ef2ad286d3927a12ef31e9e9fec1a369163ca8c5`.
Complete log SHA-256: `d3066fb1c6b0c2713405cbf4105ce37d8de5ceb4af6b3b6407b2a49126724c8c`.
The actual diagnostic agent executable SHA-256 is
`db20be9081afafd2a15a3b451547ef04855ae52ec9b7cd6ee63fb3cb0e0be478`.

The exact qualification Namespace is removed and absence confirmed. Production
journals are byte-identical before/after; all live UNF Pods remain Ready without
restart on `45d85d5`. Full current/retained logs are reviewed: current cl02 has
464 warnings (407 bounded flow-history, 45 peer-proof retries, eight bounded
topology-history, three existing-clsact notices, one attestation-row rejection);
retained CRI has 5,036 warnings in 21 categories. No production ERROR, partial or
non-JSON retained record is found. The diagnostic's panic/error is retained, not
filtered into a clean result. Warnings remain stabilization findings.

## Correction

Unconfigured controller-client construction now uses the fallible builder and
propagates system-trust errors through normal dataplane supervision. Main also
observes its task set: any unexpected exit or panic clears readiness and enters
service shutdown. When a finishing task already queued a more specific failure,
that cause is retained. Local regressions cover panic, unexpected normal exit and
the queued-error race. This does not swallow a panic or restart a failed task.

The diagnostic image receives the public distribution CA bundle from the frozen
production image. The expanded real-agent fixture additionally overrides both
native certificate paths to absent private locations and requires a normal
exit-1 trust-construction error, not panic or timeout. Normal-trust runs still
reach the deliberate missing-ELF boundary; all startup/reopen/refusal and prior
native/kernel/socket gates remain mandatory. Rebuild and pass cl02 again before
identical-image Kind. No production rollout, journal reset or Phase 9 promotion
is part of this correction.
