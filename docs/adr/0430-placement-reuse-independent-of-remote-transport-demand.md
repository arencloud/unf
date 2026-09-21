# ADR 0430: Placement reuse independent of remote transport demand

Date: 2026-09-21

Status: implemented and locally verified; production qualification pending

Pure-local Required workloads need not produce any remote Required transport
decision. Requiring that decision before fetching placement would make their
locality bank impossible to produce. The agent now acquires authenticated
placement for every exact admitted Node plan, including Native/empty-decision
plans. This is topology evidence, not a Native exception or policy grant.

The reuse key remains the complete placement context: cluster ID, recipient
Node name/UID, membership revision, identity epoch/revision and routing revision.
A changed transport/key generation, policy/Service/egress revision or plan digest
does not independently invalidate that placement. Both completed replay and
an in-flight nonce-bound request survive unrelated plan churn. Status associates
the evidence with the latest plan digest without treating that digest as its
authentication. An applied-context change still cancels and withdraws; journal
selection and actual kernel fence/dispatch checks remain mandatory.

Status explicitly reports `acquisition: allAdmittedPlans`. The existing scoped
reply gate gains an explicit `UNF_REQUIRED_REPLY_LOCALITY_ACQUISITION=all-plans`
mode for this runtime. Native baseline and post-cleanup checks require a fresh
exact replayed cut, allowing a strictly empty or valid remaining journal
inventory. They do not claim the placement cache retired merely because a
Required policy disappeared. Actual fixture UID/nonce retirement retains its
separate positive CNI checks. The default `required-only` qualifier remains for
the unchanged historical `45d85d5` runtime; it must not be used to qualify this
new acquisition behavior.

This removes redundant replay/preparation structurally; no CPU/RSS/throughput
improvement is claimed without S1 measurements. Global identity/routing churn
still invalidates the full cut. Production policy-first packet/reply wiring,
offline restart continuity and L3/L4/L5/Q remain open. The diagnostic already
building from fixed `5f03031` source does not qualify these newer changes.

Local checks: 908 workspace tests pass, 26 explicitly ignored; strict all-target
workspace Clippy passes. Placement gate mutations pass 2 positive/105 negative
cases; inventory gates pass 7 positive/65 negative cases, including all-plans
empty inventory and malformed/partial counter rejection. Formatting and shell
syntax checks pass. These do not replace cl02-first live runtime validation.
