# ADR 0045: Bounded durable topology history

Status: Accepted and live verified on dual-stack Kind

## Context

Topology schema v3 provides a precise current-state fence, but operators cannot
reconstruct a recent Service/backend lifecycle or correlate older flow evidence
after the current topology advances. A controller restart also erased any
in-memory timeline. History must remain advisory and bounded, must not introduce
a required database, and must preserve the controller epoch so revision values
from different processes cannot be confused.

## Decision

Topology-history schema v1 retains the newest 32 complete topology schema-v3
snapshots. Each entry carries its original source epoch, topology and identity
revisions, and capture time. `GET /v1/topology/history` accepts inclusive
`since_revision`, `until_revision`, `since_unix_ms`, and `until_unix_ms` bounds
plus a 1–32 newest-first limit. The response makes matched/returned counts,
truncation, in-memory eviction, checkpointed snapshots, and durable omissions
explicit.

Every semantic Pod, Node, Service, or EndpointSlice revision captures one
snapshot. Kubernetes watcher initialization is coalesced: object-by-object replay
still advances the current topology revision, but history records one completed
snapshot instead of transiently flooding the ring. Recording the same
epoch/revision fence replaces that newest entry rather than creating invalid
duplicates.

The controller checkpoints history at most every two seconds into the
pre-created `unf-topology-history` ConfigMap. RBAC permits only exact-name `get`
and `patch`. Serialization starts with all 32 entries and repeatedly halves the
newest retained subset until it fits below 900,000 bytes; omissions remain
visible. Startup validates checkpoint schema, capacity, topology schema,
timestamps, unique epoch/revision fences, strictly increasing revisions, and
future clock skew before restoring. The restored latest revision becomes the
base for watcher reconstruction, while old entries keep their original epoch.

`unfctl topology-history` exposes relative or absolute capture-time windows,
revision bounds, limits, and table/JSON/YAML output.

## Verification

State tests prove eviction, combined windows, newest-first truncation, adaptive
checkpoint omission, exact restoration, and rejection of malformed schema or
revision ordering. Controller tests prove semantic capture and initialization
coalescing. `make kind-topology-history-test`, included in `make kind-test`,
creates a selectorless Service and EndpointSlice, records not-ready, ready,
backend-deleted, and Service-deleted revisions, verifies queries and exact RBAC,
waits for the checkpoint, replaces the controller, and requires the exact old
epoch/revision/capture-time fence to survive with zero agent replacements and no
persistence errors.

## Consequences

Operators can correlate recent topology transitions with policy and flow
revisions without running an external database. Complete snapshots make each
entry independently portable and avoid patch-chain corruption, at the cost of a
small 32-revision window and potentially fewer durable entries for large
clusters. This is not an audit log or HA store. External topology databases,
pagination, topology diffs, and additional external export transports remain
separate work.
