# ADR 0309: Dependency-Aware Namespace Invalidation

Date: 2026-09-13

Status: implemented with local regressions; immutable cl02-first qualification pending

ADR 0308 records a real cl02 packet interruption during empty-namespace churn.
Remove one unnecessary cause of global policy work: keep namespace label
storage up to date, but invalidate policy only when a fabric dependency exists
or the initial nonzero policy authority must be established. Inspect dependencies
under the existing policy-state write guard, with no new unbounded cache.

Pod records, including host-network Pods, retain invalidation. Conservatively
retain it for Service-only namespaces and orphaned EndpointSlice sources, so
watch ordering cannot suppress a needed update. The synthetic
`openshift-host-network` peer namespace always invalidates even without a Pod.
Existing relist reset/readiness behavior remains unchanged. Later Pod events
advance policy and join against the most recently stored namespace labels.
Required encryption, packet revision fencing, map limits and wire schemas are
unchanged; no missing-authority fallback is introduced.

Add the fixed-cardinality counter
`unf_controller_namespace_policy_invalidations_skipped_total`, without
per-namespace labels or per-event log messages. This makes eliminated work
observable without adding a high-cardinality metric or claiming a CPU saving.
The scan short-circuits on the first dependency and allocates no dependency
index. Its cost and wider controller snapshot/telemetry work still need scale
profiling; this change does not remove all CNI limits or make updates atomic.

The new empty-namespace regression failed on the previous implementation. It
now checks the nonzero cold-start floor, stable policy snapshot/revision through
create/relabel/delete, stored labels used by a future Pod, and encoded metric
count. Occupied namespace tests cover Pod, host Pod, Service, EndpointSlice and
synthetic gateway dependencies, including deletion and stable identity revision.
The existing namespace-label test now actually supplies an affected workload.

`cargo test --workspace`: 747 passed, 25 explicit specialized ignores. Strict
all-target/all-feature workspace Clippy, formatting and the Native qualifier's
local tests pass. Ignored evidence is under `.artifacts/s1-namespace-noop-*`.

The continuity qualifier now additionally requires a stable nonzero policy
revision and at least three skipped invalidations over the completed mutation
window. Zero failed connection samples, all eight paths before/during/after,
exact cleanup and fleet convergence are still mandatory. Build and verify exact
image provenance, deploy/test cl02 first, then matching-image Kind only after
cl02 passes. The old failed window is retained. Phase 9, Required locality/reply
coverage, general update continuity and S1–S5 remain open.
