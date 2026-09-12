# ADR 0278: Checkpoint persistence as a qualification condition

Date: 2026-09-12

Status: Implemented in the cl02 harness; successor run pending

The previous gate could pass traffic while intermediate generation-checkpoint
writes failed. A planned controller replacement also resets its process-local
error counter. Before every planned baseline/controller replacement, and after
Required migration, fixture convergence, replacement recovery and final Native
cleanup, record the controller's writes/errors, Pod, restart count, memory limit
and stored checkpoint descriptor.

Require positive writes, zero persistence errors, zero container restarts, the
normal 2-GiB limit, a supported exact codec/version pair and unchanged stored/
decoded bounds. Final Native cleanup additionally requires a v1/gzip checkpoint
for the documented older-reader boundary. Failed checks stop qualification;
the existing cleanup trap still restores the acknowledged lab baseline.

Successful evidence contains these observations in `checkpointPersistence`.
Pure fixture tests reject missing/error counters, no writes, restarts, enlarged
memory limits, unsupported codec/version combinations and excessive sizes. The
static OpenShift gate requires the checks to remain wired. This observes
persistence outcomes; semantic recovery is independently exercised by actual
controller replacement and the compact-store regression.
