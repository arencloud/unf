# ADR 0044: Shadow rollout and offline impact analysis

Status: Accepted and live verified on dual-stack Kind

## Context

Shadow enforcement already preserves forwarding while exporting actual and
counterfactual policy provenance. Operators still need a bounded rollout report
that answers how much observed traffic a shadow policy would affect, and they
must be able to review captured evidence without continued access to the cluster
or controller.

Candidate simulation is a different operation: it re-evaluates a proposed
resource against current topology and policy. Shadow impact must instead report
the decisions actually produced by the dataplane and must not silently depend on
current cluster state.

## Decision

`unf-state` defines shadow-impact schema v1 and a pure analyzer over flow-history
snapshot schema v4. It validates the snapshot schema, returned-entry query count,
nonzero observations, and receive timestamp order before producing a report.
The report retains the history source epoch, revision, and query metadata.

Aggregation is both logical-flow and observation weighted. It separates actual
allow plus shadow deny, actual deny plus shadow allow, equal verdicts, and other
verdict changes; counts full decision/provenance changes; identifies affected
workloads and shadow policy IDs; and returns every bounded shadow-bearing flow
with its actual/shadow decisions, timestamps, reporting Nodes, and observation
count.

`unfctl policy shadow-impact` obtains a live snapshot and accepts the same
last-received bounds and newest-first limit as `unfctl flows`. With
`--flows-file`, it reads JSON or YAML locally. File mode conflicts with live
query flags and performs no network request; the controller URL is irrelevant.
Both modes support table, JSON, and YAML output.

## Verification

Unit tests prove observation weighting, policy/workload aggregation, offline
source attribution, command parsing, live/file flag separation, and fail-closed
rejection of stale or inconsistent snapshots. The complete two-node Kind gate
switches a native policy to Shadow, permits TCP/9090, requires recorded
actual-Allow/shadow-Deny provenance, and saves the corresponding history. It
then verifies the live report and repeats JSON plus table analysis from the saved
file while configuring an unreachable controller URL.

## Consequences

Operators can quantify a real shadow rollout and move its bounded evidence into
an offline review or change-approval workflow. Results reflect retained aggregate
events, not packet-by-packet chronology, and inherit flow-history eviction,
checkpoint, and query truncation boundaries. The analyzer does not import
arbitrary flow shapes into candidate simulation and does not claim that captured
traffic represents future traffic.
