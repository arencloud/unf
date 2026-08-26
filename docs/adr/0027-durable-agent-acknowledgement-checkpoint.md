# ADR 0027: Durable agent acknowledgement checkpoint

Status: Accepted and live verified on OpenShift

## Context

ADRs 0023 and 0024 authenticate agent acknowledgements and protect them in
transit, but the controller retained accepted reports only in memory. Controller
replacement erased the last receive time and applied revisions for every node,
so operators temporarily saw missing agents instead of authenticated last-known
status. Persisting each two-second heartbeat as an independent Kubernetes write
would create node-proportional API write amplification.

Durability must not let a report from the prior controller process satisfy the
new process's convergence gate. Corrupt or administrator-modified state must also
fail closed rather than become trusted acknowledgement evidence.

## Decision

The base deployment creates ConfigMap `unf-agent-acknowledgements` in
`unf-system` without declaring its data field. The controller service account has
only `get` and `patch` on that exact resource name; it cannot create or delete
ConfigMaps. Server-side apply field ownership isolates `reports.json` from normal
manifest reapplication.

After TokenReview, Pod UID, Node placement, claim, and report-shape validation,
the controller updates its in-memory report and marks the checkpoint dirty. One
background task serializes the complete map at most every two seconds, bounding
write rate independently of node count. The schema-v1 document contains at most
1,024 node-keyed schema-v2 reports and their last controller receive timestamps.
New node reports fail closed when that capacity is exhausted. Deleting a Node
retires its entry and schedules another checkpoint. Completion of each initial
Node listing also removes restored entries for Nodes deleted while the controller
was unavailable.

Connected startup reads and validates the checkpoint before Kubernetes watchers
or API listeners start. It rejects malformed JSON, unknown schema, excess entries,
invalid reports, node-key mismatches, zero timestamps, and timestamps more than
60 seconds in the future. No partial subset is restored. A missing data field is
a valid empty first deployment; an unavailable or corrupt ConfigMap prevents
startup until an operator repairs it.

Restored reports preserve their original timestamp and controller epoch. They may
appear as last-known reporting or stale state, but `all_converged` remains false
for the new randomly generated controller epoch until agents submit fresh,
authenticated acknowledgements for current identity and policy revisions.

Metrics expose checkpoint writes, errors, and the startup restore count:

- `unf_agent_report_persistence_writes_total`;
- `unf_agent_report_persistence_errors_total`; and
- `unf_agent_reports_restored_total`.

## Verification

Unit tests round-trip a valid store, reject schema/key/timestamp violations, and
prove both observed and offline Node deletion retire the report and mark the
checkpoint dirty. Strict workspace formatting, lint, tests, eBPF build,
rendering, and server-side apply remain required.

`make openshift-agent-report-retention-test` waits for one valid checkpoint entry
per selected worker, verifies exact-name RBAC, records agent Pod UID/restart
tuples, and replaces the controller. The new process must report the exact number
of restored entries and zero persistence errors, then reconverge to its new epoch
and advance the durable receive timestamp without replacing or restarting an
agent.

## Consequences

Controller replacement preserves authenticated last-known agent state and
bounded receive history while maintaining epoch-based convergence integrity.
Checkpoint write frequency is constant for one controller rather than linear in
the number of reporting agents. No PVC, external database, or static credential
is introduced.

The checkpoint is designed for the current single-controller Deployment. It does
not provide leader election, multi-writer conflict resolution, historical report
versions, or durable desired state, identity allocation, or flow history.
ConfigMap size and the explicit 1,024-node cap define the current scale boundary.
HA control planes and larger fleets require a measured storage design rather than
silently expanding this prototype.
