# ADR 0281: Authenticated durable-admission frontier recovery

Date: 2026-09-12

Status: Implemented; platform qualification pending

The cl02 incident in ADR 0279 exposed a missing controller write between two
durable Node generations. Replaying only the newest prepared fact concealed the
exact admitted predecessor and correctly failed the frontier's predecessor check.

Agents now publish a separate public fact only when its recipient and complete
checkpoint exactly equal their validated durable admission. Active, pending and
tombstoned-predecessor journal slots may supply that exact fact; preparation alone
cannot. The authenticated internal admitted-fact endpoint uses the same current
Pod, service-account and authoritative Node-UID checks as prepared publication.
An older controller's HTTP 404 preserves rolling compatibility; all other
non-202 responses remain errors.

The controller retains at most one admitted fact per authoritative Node,
separately from prepared facts. No majority, mixed-generation or partial cut can
recover a frontier. A complete admitted cut must equal the current frontier or
extend its exact per-Node predecessor with unchanged membership. This also
reconstructs acknowledgements lost in the same controller write gap. Validation
finishes before either frontier or acknowledgements change. Skipped history,
equivocation and replacement are refused; an absent base cannot be invented.
Older admissions never regress the frontier. Ordinary prepared publication keeps
its existing all-Node acknowledgement barrier.

Only changed recovery marks persistence dirty. Unchanged, already-recovered
admission replay avoids fleet candidate reconstruction. Recovery changes
controller backpressure, not kernel, route, activation or packet authority; the
agent must still independently revalidate local proofs. No journal deletion,
manual checkpoint rewriting or weakening of Required semantics is involved.

Five-Node regressions cover the lost intermediate frontier with a newer prepared
cut, incomplete admission, lost predecessor receipts, idempotent replay and
subsequent normal publication. Negative cases cover skipped history, absent base,
changed UID, mutation and same-generation equivocation with no partial receipts.
Controller tests fence replaced Pods/Nodes and avoid dirty writes on replay;
agent tests distinguish preparation from exact durable admission. An opt-in test
replays the actual public cl02 ConfigMap and five active facts without contacting
or mutating the cluster. Captures remain ignored local evidence.

Verification: 728 workspace tests passed (25 specialized tests excluded by the
generic invocation); strict all-target/all-feature workspace lint and the
OpenShift qualification static gate passed. The separate cl02 capture replay
passed, reconstructing the missing frontier with exact successor validation.

Local checks precede image publication. Required platform order is cl02, then
fresh Kind using identical runtime images. Until both full lifecycle gates pass,
Phase 9 and the stabilization/scale milestones remain open.
