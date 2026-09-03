# ADR 0125: Require bilateral egress application acknowledgements

**Status:** Accepted and implemented for the Phase 8.5 application-acknowledgement slice

## Context

Authenticated source and selected-gateway projections were independently
validated, but fetching a projection was still being treated as sufficient
source admission. A successful response proves only delivery. It does not prove
that the source committed and read back its map bank, or that a selected gateway
adopted the exact projection or withdrawal. Activating steering on that signal
could send traffic toward a gateway that cannot reproduce the bilateral
contract.

## Decision

Projection delivery and application are separate states. A source fetch records
one pending projection bound to the authenticated agent Pod and does not admit
that source for gateway distribution. After transactional source-map apply,
readback, pointer activation, and durable authority update, the agent posts a
strict schema-v1 acknowledgement binding the controller epoch, projection and
contract revisions, recipient, contract digest, active bank, and source count.
Only exact acknowledgement admits the source contract for selected-gateway
distribution.

A gateway fetch similarly records one pending projection. After independent
admission and monotonic gateway-ledger adoption, the gateway posts exact
schema-v1 evidence binding the epoch, projection revision, recipient, digest,
contract/source counts, and active-versus-withdrawn action. An empty withdrawal
therefore requires positive application evidence; silence is not withdrawal.
Exact retries are idempotent, while unknown fields, stale revisions, digest or
count mutation, active/withdrawn mutation, and a different Pod UID fail closed.

The controller exposes bilateral readiness independently from issuance and
application counts. A source is ready only while its acknowledged projection is
current, its issuing Pod identity still matches watched state, and every
selected gateway has acknowledged a current non-withdrawal projection that
contains the exact source contract. Desired-state invalidation and Node removal
clear pending/application evidence. Controller restart also intentionally loses
this runtime evidence; periodic exact agent replay reacquires it before future
activation. No stale acknowledgement is restored as authority.

## Consequences

Projection receipt can no longer make a source eligible for gateway
distribution. Replacement Pods cannot inherit another process's evidence, and
active evidence cannot acknowledge withdrawal. The status endpoint reports
accepted source applications, gateway applications, and bilaterally ready
sources without high-cardinality labels.

This slice does not configure a gateway address, apply gateway NAT maps, attach
source/gateway steering, transition an egress identity from `Fenced` to
`Active`, or claim packet behavior. Gateway acknowledgement currently proves
validated monotonic host-control ledger adoption. The next slice consumes the
readiness predicate while implementing policy-first TC steering and
collision-safe dual-stack TCP/UDP NAT/reverse state.

`make egress-application-ack-test` inherits every earlier Phase 8.5 gate and
adds exact source/gateway evidence validation, strict wire decoding, delivery
versus application separation, Pod replacement rejection, idempotent replay,
stale/mutated evidence rejection, invalidation, explicit acknowledged
withdrawal, status counts, and strict Clippy.
